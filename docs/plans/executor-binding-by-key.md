# Executor binding by process key

**Goal.** An executor bound by a flow's opener is the opener's process key (`ProcKey`, `tgid` with `start_ns`) as the reconciler recorded it from the sensor's connect, in every path that binds one. Today `Spans::http_request` and `Spans::flow` pass the opener's `tgid` to `name_executor`, which resolves it again with `State::attribute(tgid, ts)` at the request's time; the binding then depends on what that pid names at that time, not on who opened the flow. After this change the binding takes the stored key itself, and pid resolution is left to provisional evidence (TLS writes, which carry only a `tgid`).

This is M5's Task 1 work (`docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 2). Branch `executor-binding-by-key`, its own pull request from `main`.

## The events

All in `crates/boxcar-audit/src/reconcile/spans.rs` unless named:

- **C, the opener known**: a flow's `net.connect` meets the sensor's `proc.tcp_connect` (`rules.rs` → `Spans::flow(flow, key)`); `flow_owners[flow] = key`.
- **R, a request**: `http.request` on (`flow`, `stream`) (`Spans::http_request`).
- **W, a TLS write**: `proc.tls_io` write by a `tgid` (`Spans::tls_write`), naming a provisional executor through `carrier` and `name_executor(…, bound = false)`.
- **O, a span opens**: `tool.open` for a request (`Spans::open`), taking the request's executor or, failing a bound one, the flow's opener.
- **K, a span closes**: `tool.close` on a flow (`close_verdict`, `apply_close`), applied only when the closer's flow was opened by the span's bound executor (or its flow's opener).
- **X, the opener exits**: its `proc.exit`; its pid may then be **P, reused**: a later process with the same `tgid` and a later `start_ns` (`State` keeps both; `attribute` picks the membership covering a time).
- **E, eviction**: `flow_owners` past `MAX_FLOW_OWNERS`, `executors` past `MAX_EXECUTORS`. A request bound by `flow` stays in `requests` today, so after its `executors` entry is evicted a later W treats it as unnamed.

## The orders that matter

1. C, R: the opener is known when the request comes. `http_request` binds at once.
2. R, C: the request comes first; `flow` binds every request seen on the flow when the opener becomes known.
3. C, X, R: the opener has exited before the request (its socket lives on in a process that inherited it). Today `attribute(tgid, ts_R)` returns the opener only while `ts_R` is within `JOIN_WINDOW_NS` of its exit, else nothing, and no bound executor is set.
4. C, X, P, R: as 3, and the pid names another process by `ts_R`. Today `attribute` returns that process, bound.
5. R, X, P, C: the opener becomes known after its pid is reused (the connect join is late); `flow` resolves `key.tgid` at `max(ts_R, ts_C)`, with the same outcome as 4.
6. W before or after R, then C: a provisional executor from a write is replaced by the bound one (unchanged).
7. O before or after the binding: the span takes the bound key (`set_span_executors`, `open`).
8. E between C and R: the opener is gone from `flow_owners`; R names no bound executor (unchanged; `open` and `close_verdict` already read `flow_owners` by key).
9. R, C, O, E of the request's `executors` entry, then W: the write fits the request, which `tls_write` no longer sees as bound, and `set_span_executors` would put a provisional key on the open span over its bound one; with two fitting writers, `unname_executor` would clear it. Moving O after W instead gives the bound opener back.

## Invariants

- **I1.** A bound executor is the `ProcKey` stored in `flow_owners` for its flow, never a key re-derived from a pid.
- **I2.** A bound executor is set whenever the flow's opener is known, whether or not that process is still alive at the request's time (orders 3, 4, 5).
- **I3.** A provisional executor still comes from `attribute(tgid, ts)` and never replaces a bound one (unchanged).
- **I4.** `open` and `close_verdict`, which already read `flow_owners` by key, agree with the executors `http_request` and `flow` set: for every order above the span's executor, its `executor_bound`, and the verdict on a close come out the same whichever of R, C, O comes first.
- **I5.** A span whose executor is bound keeps it: no provisional naming replaces it and no revocation clears it, whatever the executor cache holds (order 9).

## The change

- `name_executor` splits in two: `bind_executor(flow, stream, key: ProcKey)`, which records `(key, true)` and updates the open spans, and the provisional path, which resolves a `tgid` with `attribute` and then records `(key, false)` through the same setter. `http_request` and `flow` call `bind_executor` with the stored key.
- A request whose flow's opener is known is done waiting: `flow` removes the flow's requests from `requests` once it binds them, and `tls_write` skips any request whose flow is in `flow_owners`.
- `set_span_executors` with a provisional executor, or with none, leaves a span whose executor is bound as it is; only `bind_executor` sets a bound one.

Nothing else changes: the windows, the bounds, eviction, and the provisional rules for requests whose opener is not known.

## Out of scope

- Provisional evidence keeps resolving a `tgid` at the request's time; a provisional executor never decides a close (`close_verdict` reads only bound executors and flow openers), so it is not this change's.
- Who opened a flow (the sensor's connect join in `rules.rs`) is taken as it is.
- `is_agent`, `reaches_agent` and the span membership rules are untouched.

## Tests

Reconciler scenarios in `crates/boxcar-audit/tests/reconcile.rs`, written first and failing before the change where they name today's behaviour:

- `a_bound_executor_is_the_flows_opener_after_it_exits` (order 3): the opener exits beyond the join window before the request; the span's executor is the opener (`executor_tgid` and its start), bound.
- `a_bound_executor_is_the_flows_opener_not_its_pids_next_process` (order 4): as above, and a new process takes the opener's pid before the request; the span's executor is the opener, and a `tool.close` on a flow the new process opened does not close the span.
- `a_late_opener_binds_by_key_after_its_pid_is_reused` (order 5): the request first, then the pid reused, then the connect join; the same outcome as order 4.
- `the_binding_is_the_same_whatever_comes_first` (orders 1, 2, 7): the same events in each order of R, C and O give the same span executor and close verdict.
- `a_bound_span_keeps_its_executor_after_the_cache_evicts_it` (order 9): R, C, O, then 256 requests on other known flows evict the request's entry, then a second process's write fits the request; and again with two fitting writers. The span's executor is the opener, still bound; an effect of the opener's child joins the span; a close on the opener's flow closes it and a close on the writer's flow does not.
- The existing executor scenarios (`the_flows_opener_is_the_executor`, `a_flows_opener_replaces_a_provisional_executor`, `an_evicted_executor_is_recovered_from_the_flow`, `a_close_from_the_executors_sibling_is_refused`, `a_close_waits_for_the_spans_own_opener`, the TLS-write ones) pass unchanged (orders 6, 8).
