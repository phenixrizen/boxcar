# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Versioned receipt/disposition rules shared by the CLI and trusted-main CI.

No GitHub writes or review invocations here. Public evidence is an owner
attestation; raw reviewer claims stay in restricted local reports.
"""

import copy
import hashlib
import json
import re

VERSION = 2
POLICY_VERSION = 3
CHECKPOINT_VERSION = 3
LIMITS = {"docs": 1, "plan": 2, "code": 3}
SCOPES = ("initial", "follow-up", "integration")
CATEGORIES = ("unclassified", "blocking", "nonblocking", "concern", "independent")
STATUSES = (
    "investigate",
    "fixed-unverified",
    "verified",
    "refuted",
    "deferred",
    "excepted",
)


class Error(Exception):
    pass


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def finding_id(attempt, index):
    return "F-" + digest([attempt, index])[:12]


def count(state, phase):
    return sum(
        r["status"] == "completed" and r["phase"] == phase
        for r in state.get("reviews", [])
    )


def migrate(state):
    """Pure recoverable migration; caller saves/publishes through its usual barrier."""
    if state["version"] in (VERSION, CHECKPOINT_VERSION):
        return state
    if state["version"] != 1:
        raise Error("unsupported checkpoint schema")
    if any(r["status"] == "pending" for r in state["reviews"]):
        raise Error("recover legacy pending attempt before migration")
    s = copy.deepcopy(state)
    s["version"] = VERSION
    s["policy_version"] = VERSION
    s["migration"] = {"from": 1, "history": {r["id"]: digest(r) for r in s["reviews"]}}
    s["findings"] = {}
    for r in s["reviews"]:
        if r["status"] != "completed":
            continue
        for i in range(max(r.get("unresolved", 0), int(r.get("outcome") != "approve"))):
            fid = finding_id(r["id"], i)
            s["findings"][fid] = {
                "id": fid,
                "sources": [[r["id"], i]],
                "severity": "unknown",
                "confidence": None,
                "history": [],
                "legacy": True,
            }
    return s


def deliverable_binding(ident, outcome, acceptance, attempts, history_digest):
    return digest(
        {
            "id": ident,
            "outcome": outcome,
            "acceptance": acceptance,
            "start_after": attempts,
            "history_digest": history_digest,
        }
    )


def begin_deliverable(state, ident, outcome, acceptance, comment):
    """An owner-authorized boundary, never an automatic session/budget reset.

    The caller checks the exact bound owner comment before publishing this
    candidate. Existing reviews, grants and finding histories remain untouched.
    """
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", ident or ""):
        raise Error("invalid deliverable identity")
    if not all(isinstance(v, str) and v.strip() for v in (outcome, acceptance)):
        raise Error("deliverable needs an outcome and acceptance criteria")
    if not isinstance(comment, int) or isinstance(comment, bool) or comment < 1:
        raise Error("deliverable needs exact owner authorization")
    s = copy.deepcopy(migrate(state))
    if any(r["status"] == "pending" for r in s["reviews"]):
        raise Error("recover pending review before changing deliverable")
    existing = next((d for d in s.get("deliverables", []) if d["id"] == ident), None)
    if existing:
        if s.get("active_deliverable") != ident or (
            existing["outcome"],
            existing["acceptance"],
            existing["comment"],
        ) != (outcome, acceptance, comment):
            raise Error(
                "deliverable identity already used; cannot rename or reset scope"
            )
        return s
    if s["version"] != CHECKPOINT_VERSION:
        s["deliverable_migration"] = {
            "from": s["version"],
            "history": {r["id"]: digest(r) for r in s["reviews"]},
            "ceilings": copy.deepcopy(s.get("ceilings", {})),
        }
        s["version"] = CHECKPOINT_VERSION
        s["policy_version"] = POLICY_VERSION
        s["deliverables"] = []
    attempts = [r["id"] for r in s["reviews"]]
    history_digest = digest(s["reviews"])
    s["deliverables"].append(
        {
            "id": ident,
            "outcome": outcome,
            "acceptance": acceptance,
            "comment": comment,
            "start_after": attempts,
            "history_digest": history_digest,
            "binding": deliverable_binding(
                ident, outcome, acceptance, attempts, history_digest
            ),
        }
    )
    s["active_deliverable"] = ident
    return s


def active_deliverable(state):
    if state.get("version") != CHECKPOINT_VERSION:
        return None
    entries = state.get("deliverables", [])
    if not entries or entries[-1].get("id") != state.get("active_deliverable"):
        raise Error("active deliverable missing or does not match authorized history")
    return entries[-1]


def deliverable_count(state, phase, ident=None):
    ident = ident or active_deliverable(state)["id"]
    return sum(
        r["status"] == "completed"
        and r["phase"] == phase
        and r.get("deliverable") == ident
        for r in state.get("reviews", [])
    )


def review_fields(state, phase):
    d = active_deliverable(state)
    return {
        "receipt_version": VERSION,
        "policy_version": POLICY_VERSION if d else VERSION,
        **(
            {
                "deliverable": d["id"],
                "deliverable_round": deliverable_count(state, phase) + 1,
            }
            if d
            else {}
        ),
    }


def capture_findings(state, verifies):
    """Immutable input fingerprints captured before sending reviewer context."""
    context = {}
    for fid in verifies:
        f = state.get("findings", {}).get(fid)
        if f is None:
            raise Error("unknown finding to verify")
        context[fid] = {
            "disposition": digest(f["history"][-1]) if f.get("history") else None,
            "sources": digest(f["sources"]),
        }
    return context


def authorization(state, phase, round_, deliverable=None, legacy=False):
    scope = None
    if state.get("version") == CHECKPOINT_VERSION and not legacy:
        ident = deliverable or active_deliverable(state)["id"]
        scope = next((d for d in state["deliverables"] if d["id"] == ident), None)
        if scope is None:
            raise Error("unknown deliverable for review authorization")
    return next(
        (
            a
            for a in state.get("authorizations", [])
            if a["phase"] == phase
            and a["round"] == round_
            and (
                (a.get("deliverable"), a.get("binding"))
                == (scope["id"], scope["binding"])
                if scope
                else not a.get("deliverable") and not a.get("binding")
            )
        ),
        None,
    )


def budget(state, phase):
    if any(r["status"] == "pending" for r in state.get("reviews", [])):
        raise Error("pending review: recover it before another invocation")
    round_ = count(state, phase) + 1
    d = active_deliverable(state)
    ceiling = (d if d else state).get("ceilings", {}).get(phase)
    if ceiling and round_ > ceiling["round"]:
        raise Error(
            f"{phase} scoped allowance exhausted at round {ceiling['round']}; owner decision required"
        )
    scoped_round = deliverable_count(state, phase) + 1 if d else round_
    if scoped_round > LIMITS[phase] and not authorization(state, phase, round_):
        raise Error(
            f"{phase} budget exhausted; scoped owner authorization required for round {round_}"
        )
    failed_ids, consecutive = failed_attempts(state, phase)
    retry = state.get("retry_authorizations", {}).get(phase, {})
    if consecutive >= 2 and (
        retry.get("failed_ids") != failed_ids
        or retry.get("binding") != digest(failed_ids)
        or retry.get("round") != round_
    ):
        raise Error(
            "two failed attempts; repair access/output and record owner retry authorization for failed-attempt digest "
            + digest(failed_ids)
        )
    return round_


def failed_attempts(state, phase):
    failed_ids, consecutive = [], 0
    for r in state.get("reviews", []):
        if r["phase"] != phase:
            continue
        if r["status"] == "failed":
            failed_ids.append(r["id"])
            consecutive += 1
        elif r["status"] == "completed":
            consecutive = 0
    return failed_ids, consecutive


def check_ledger(state, check_auth):
    """Validate historical policies and explicitly authorized scope boundaries."""
    ids = [r["id"] for r in state["reviews"]]
    if len(ids) != len(set(ids)):
        raise Error("duplicate review attempt IDs")
    historical = state.get("migration", {}).get("history", {})
    if not set(historical).issubset(ids):
        raise Error("migration lost review history")
    for ident, expected in historical.items():
        if digest(next(r for r in state["reviews"] if r["id"] == ident)) != expected:
            raise Error("historical attempt was rewritten")
    deliverables = check_deliverables(state, check_auth)
    if state.get("version") in (VERSION, CHECKPOINT_VERSION):
        for r in state["reviews"]:
            if r["status"] == "completed" and r.get("policy_version", 1) == 1:
                expected = [
                    finding_id(r["id"], i)
                    for i in range(
                        max(r.get("unresolved", 0), int(r.get("outcome") != "approve"))
                    )
                ]
                if any(fid not in state.get("findings", {}) for fid in expected):
                    raise Error("legacy finding lost during migration")
    for phase in ("docs", "plan", "code"):
        done = [
            r
            for r in state["reviews"]
            if r["phase"] == phase and r["status"] == "completed"
        ]
        if [r["round"] for r in done] != list(range(1, len(done) + 1)):
            raise Error("inconsistent review counts")
        for r in done:
            policy = r.get("policy_version", 1)
            if policy not in (1, VERSION, POLICY_VERSION):
                raise Error("unknown review policy")
            if (
                state.get("version") in (VERSION, CHECKPOINT_VERSION)
                and policy == 1
                and historical.get(r["id"]) != digest(r)
            ):
                raise Error("legacy review changed or was added after migration")
            limit = {"docs": 1, "plan": 2, "code": 5 if policy == 1 else 3}[phase]
            scoped_round = (
                r["deliverable_round"] if policy == POLICY_VERSION else r["round"]
            )
            if scoped_round > limit:
                a = authorization(
                    state,
                    phase,
                    r["round"],
                    r.get("deliverable"),
                    legacy=policy != POLICY_VERSION,
                )
                if not a:
                    raise Error("review budget exceeded without owner authorization")
                check_auth(
                    phase,
                    r["round"],
                    a["comment"],
                    "authorize",
                    *([a["binding"]] if policy == POLICY_VERSION else []),
                )
            if policy in (VERSION, POLICY_VERSION):
                validate_receipt(state, r)
                if policy == POLICY_VERSION and renewed_initial(state, r):
                    a = authorization(state, phase, r["round"], r["deliverable"])
                    if not a:
                        raise Error(
                            "renewed initial review needs scoped owner authorization"
                        )
                    check_auth(
                        phase, r["round"], a["comment"], "authorize", a["binding"]
                    )
        legacy_done = [r for r in done if r.get("policy_version", 1) != POLICY_VERSION]
        ceiling = (
            state["deliverable_migration"].get("ceilings", {})
            if deliverables
            else state.get("ceilings", {})
        ).get(phase)
        if ceiling:
            check_auth(phase, ceiling["round"], ceiling["comment"], "ceiling")
            if len(legacy_done) > ceiling["round"]:
                raise Error("scoped review allowance exceeded")
    # A retry grant names the exact failures preceding an invocation. Reusing
    # a comment cannot silently expand it to cover a newly failed attempt.
    prefix = []
    for r in state["reviews"]:
        failed_ids, consecutive = failed_attempts({"reviews": prefix}, r["phase"])
        if r.get("policy_version") in (VERSION, POLICY_VERSION) and consecutive >= 2:
            grant = r.get("retry", {})
            round_ = count({"reviews": prefix}, r["phase"]) + 1
            if (
                grant.get("failed_ids") != failed_ids
                or grant.get("binding") != digest(failed_ids)
                or grant.get("round") != round_
            ):
                raise Error("review retry grant missing or reused for other failures")
            check_auth(r["phase"], round_, grant["comment"], "retry", grant["binding"])
        prefix.append(r)
    # Preserve policy 1's actual checkpoint requirement, without retroactive v2 permission.
    old_code = [
        r
        for r in state["reviews"]
        if r["phase"] == "code"
        and r["status"] == "completed"
        and r.get("policy_version", 1) == 1
    ]
    if (
        len(old_code) > 3
        and old_code[2]["outcome"] != "approve"
        and not state.get("triage")
    ):
        raise Error("historical third-round triage missing")


def check_deliverables(state, check_auth):
    """The full attempt prefix binds a grant to exactly one point in history."""
    if state.get("version") != CHECKPOINT_VERSION:
        if any(r.get("policy_version") == POLICY_VERSION for r in state["reviews"]):
            raise Error("deliverable review requires checkpoint schema 3")
        return []
    active_deliverable(state)
    entries = state["deliverables"]
    ids = [r["id"] for r in state["reviews"]]
    migration = state.get("deliverable_migration", {})
    historical = migration.get("history", {})
    if migration.get("from") != VERSION or set(historical) != set(
        entries[0]["start_after"]
    ):
        raise Error("deliverable migration missing immutable legacy history")
    for r in state["reviews"][: len(historical)]:
        if historical.get(r["id"]) != digest(r):
            raise Error("historical attempt was rewritten during deliverable migration")
    seen, previous = set(), 0
    for ordinal, d in enumerate(entries, 1):
        boundary = d.get("start_after", [])
        if (
            d.get("id") in seen
            or len(boundary) < previous
            or boundary != ids[: len(boundary)]
            or d.get("history_digest") != digest(state["reviews"][: len(boundary)])
            or d.get("binding")
            != deliverable_binding(
                d.get("id"),
                d.get("outcome"),
                d.get("acceptance"),
                boundary,
                d.get("history_digest"),
            )
        ):
            raise Error("deliverable identity, scope or attempt boundary changed")
        check_auth("deliverable", ordinal, d["comment"], "deliverable", d["binding"])
        seen.add(d["id"])
        previous = len(boundary)
        end = (
            len(entries[ordinal]["start_after"]) if ordinal < len(entries) else len(ids)
        )
        per_phase = {phase: 0 for phase in LIMITS}
        scoped_reviews = state["reviews"][previous:end]
        for r in scoped_reviews:
            if (
                r.get("policy_version") != POLICY_VERSION
                or r.get("deliverable") != d["id"]
                or r.get("deliverable_round") != per_phase[r["phase"]] + 1
            ):
                raise Error("review changed deliverable or reset its completed count")
            if r["status"] == "completed":
                per_phase[r["phase"]] += 1
        for phase, ceiling in d.get("ceilings", {}).items():
            if (ceiling.get("deliverable"), ceiling.get("binding")) != (
                d["id"],
                d["binding"],
            ):
                raise Error("review ceiling is not bound to this deliverable")
            check_auth(
                phase,
                ceiling["round"],
                ceiling["comment"],
                "ceiling",
                ceiling["binding"],
            )
            if any(
                r["phase"] == phase
                and r["status"] == "completed"
                and r["round"] > ceiling["round"]
                for r in scoped_reviews
            ):
                raise Error("scoped review allowance exceeded within deliverable")
    return entries


def receipt(state, ident):
    found = [
        r for r in state["reviews"] if r["id"] == ident and r["status"] == "completed"
    ]
    if len(found) != 1:
        raise Error("unknown or incomplete prior review")
    return found[0]


def validate_receipt(state, r):
    if r.get("receipt_version") != VERSION or r.get("scope") not in SCOPES:
        raise Error("invalid review receipt schema/scope")
    inputs = r.get("inputs", {})
    if inputs != {
        "head": r["commit"],
        "base": r["base_sha"],
        "merge_base": r.get("merge_base"),
    } or not all(re.fullmatch("[0-9a-f]{40,64}", v or "") for v in inputs.values()):
        raise Error("review inputs missing or mismatched")
    if not r.get("result_digest") or not isinstance(r.get("finding_ids"), list):
        raise Error("missing structured review output evidence")
    if any(fid not in state.get("findings", {}) for fid in r["finding_ids"]):
        raise Error("review finding lost from ledger")
    if r["outcome"] not in ("approve", "needs-attention"):
        raise Error("invalid completed review outcome")
    if r["outcome"] == "needs-attention" and not r["finding_ids"]:
        raise Error("unexplained review verdict")
    validate_scope(state, r)


def earlier_reviews(state, r):
    for index, previous in enumerate(state["reviews"]):
        if previous["id"] == r["id"]:
            return state["reviews"][:index]
    return state["reviews"]


def renewed_initial(state, r):
    return (
        r.get("policy_version") == POLICY_VERSION
        and r.get("scope") == "initial"
        and any(
            p["status"] == "completed"
            and p["phase"] == r["phase"]
            and p.get("deliverable") == r.get("deliverable")
            for p in earlier_reviews(state, r)
        )
    )


def validate_scope(state, r, check_auth=None):
    if r.get("scope") not in SCOPES:
        raise Error("invalid review scope")
    if r.get("policy_version") == POLICY_VERSION:
        context = r.get("finding_context")
        if (
            not isinstance(context, dict)
            or set(context) != set(r.get("verifies", []))
            or any(
                not isinstance(value, dict)
                or set(value) != {"disposition", "sources"}
                or not re.fullmatch("[0-9a-f]{64}", value.get("sources") or "")
                or (
                    value.get("disposition") is not None
                    and not re.fullmatch("[0-9a-f]{64}", value["disposition"])
                )
                for value in context.values()
            )
        ):
            raise Error(
                "review lacks immutable finding context captured before invocation"
            )
    prior_ids = r.get("prior", [])
    if r["scope"] != "initial" and (
        not prior_ids or not r.get("rationale", "").strip()
    ):
        raise Error("focused scope needs prior receipts and continuity rationale")
    before = earlier_reviews(state, r)
    source_reports = {
        source[0]
        for fid in r.get("verifies", [])
        for source in state.get("findings", {}).get(fid, {}).get("sources", [])
    }
    same_phase = []
    for ident in prior_ids:
        if ident not in [p["id"] for p in before]:
            raise Error("prior receipt must precede this review")
        p = receipt(state, ident)
        if p["phase"] != r["phase"] and (
            r.get("policy_version") != POLICY_VERSION or ident not in source_reports
        ):
            raise Error("prior receipt has another phase")
        if p["phase"] == r["phase"]:
            same_phase.append(p)
            if r["scope"] == "follow-up" and p["base_sha"] != r["base_sha"]:
                raise Error("target changed; use integration or renewed initial scope")
    if r["scope"] != "initial" and not same_phase:
        raise Error("focused review requires a prior receipt of its own phase")
    if r.get("material_change") and r["scope"] != "initial":
        raise Error("material change requires initial review")
    if any(fid not in state.get("findings", {}) for fid in r.get("verifies", [])):
        raise Error("unknown finding to verify")
    if renewed_initial(state, r):
        round_ = r.get("round", count({"reviews": before}, r["phase"]) + 1)
        a = authorization(state, r["phase"], round_, r["deliverable"])
        if not r.get("material_change") or not a:
            raise Error(
                "renewed initial review needs material change and scoped owner authorization"
            )
        if check_auth:
            check_auth(r["phase"], round_, a["comment"], "authorize", a["binding"])


def high_impact(f):
    return f.get("severity") in ("critical", "high") or any(
        o.get("severity") in ("critical", "high") and o["source"] in f["sources"]
        for o in f.get("observations", [])
    )


def register_result(state, r, result):
    """Preserve raw result separately; never put its prose in public checkpoints."""
    findings = state.setdefault("findings", {})
    ids = []
    claims = result["findings"] or ([{}] if result["verdict"] != "approve" else [])
    for i, claim in enumerate(claims):
        # The supported plugin schema has no ID field. A reviewer may echo a known
        # opaque ID in its title. Otherwise retain a new entry; do not guess identity.
        matches = re.findall(r"\bF-[a-f0-9]{12}\b", claim.get("title", ""))
        fid = (
            matches[0]
            if len(matches) == 1 and matches[0] in r.get("verifies", [])
            else finding_id(r["id"], i)
        )
        f = findings.setdefault(
            fid,
            {
                "id": fid,
                "sources": [],
                "history": [],
                "severity": claim.get("severity", "unknown"),
                "confidence": claim.get("confidence"),
            },
        )
        for event in f["history"]:
            event.setdefault("sources_seen", len(f["sources"]))
        source = [r["id"], i]
        if source not in f["sources"]:
            f["sources"].append(source)
        observation = {
            "source": source,
            "severity": claim.get("severity", "unknown"),
            "confidence": claim.get("confidence"),
        }
        if observation not in f.setdefault("observations", []):
            f["observations"].append(observation)
        # A repeated finding must be investigated again. Earlier resolution is history.
        if f["history"]:
            previous = f["history"][-1]
            f["history"].append(
                {
                    "category": "concern" if high_impact(f) else previous["category"],
                    "status": "investigate",
                    "sources_seen": len(f["sources"]),
                    "evidence": "Reviewer raised this finding again.",
                    "consequence": "Reconcile the new claim before readiness.",
                    **(
                        {"tracking": previous["tracking"]}
                        if previous.get("tracking")
                        else {}
                    ),
                    "head": r["commit"],
                    "base": r["base_sha"],
                }
            )
        ids.append(fid)
    r["finding_ids"] = ids
    r["result_digest"] = digest(result)


def disposition(state, fid, data, head, base, confidential=False):
    f = state.get("findings", {}).get(fid)
    if not f:
        raise Error("unknown finding ID")
    allowed = {"category", "status", "evidence", "consequence", "tracking", "comment"}
    if (
        set(data) - allowed
        or data.get("category") not in CATEGORIES
        or data.get("status") not in STATUSES
    ):
        raise Error("invalid finding disposition")
    if not all(
        isinstance(data.get(k), str) and data[k].strip()
        for k in ("evidence", "consequence")
    ):
        raise Error("disposition needs evidence and consequences, not confidence alone")
    category, status = data["category"], data["status"]
    dangerous = high_impact(f) or any(
        e["category"] in ("blocking", "concern") for e in f["history"]
    )
    if dangerous and category not in ("blocking", "concern"):
        raise Error(
            "blocking finding/concern cannot disappear by reclassification; verify, refute or obtain a specific exception"
        )
    if status == "deferred" and category not in ("nonblocking", "independent"):
        raise Error("only nonblocking/independent work may be deferred")
    tracking = (
        r"[\w.-]+/[\w.-]+#GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
        if confidential
        else r"(?:[\w.-]+/[\w.-]+)?#[1-9][0-9]*"
    )
    if category == "independent" and not re.fullmatch(
        tracking, data.get("tracking", "")
    ):
        raise Error(
            "independent defect requires separate private advisory tracking"
            if confidential
            else "independent defect requires separate issue tracking"
        )
    if category == "unclassified" and status not in ("investigate", "fixed-unverified"):
        raise Error("classify legacy/unknown finding with evidence first")
    if status == "excepted" and not isinstance(data.get("comment"), int):
        raise Error("specific owner finding exception required")
    event = {**data, "head": head, "base": base, "sources_seen": len(f["sources"])}
    f["history"].append(event)
    return event


def carry_forward(state, ident, finding_ids, rationale, confidential=False):
    """One explicit verification batch carries applicable settled dispositions.

    This does not change historical findings or verdicts. Every source report
    must be directly supplied to the reviewer; silence about an unknown claim
    or a new occurrence is never evidence of its resolution.
    """
    if state.get("version") != CHECKPOINT_VERSION:
        raise Error("carry-forward requires checkpoint schema 3")
    if not isinstance(rationale, str) or not rationale.strip():
        raise Error("carry-forward needs a continuity rationale")
    r = receipt(state, ident)
    if r.get("policy_version") != POLICY_VERSION:
        raise Error(
            "carry-forward requires a policy 3 review with original source context"
        )
    validate_receipt(state, r)
    if not finding_ids or len(finding_ids) != len(set(finding_ids)):
        raise Error("carry-forward needs unique finding IDs")
    batch = {
        "receipt": ident,
        "head": r["commit"],
        "base": r["base_sha"],
        "rationale": rationale,
        "findings": {},
    }
    for fid in finding_ids:
        f = state.get("findings", {}).get(fid)
        if not f or not f["history"] or fid not in r.get("verifies", []):
            raise Error(
                "carry-forward finding was not classified and explicitly reviewed"
            )
        e = f["history"][-1]
        if not {source[0] for source in f["sources"]}.issubset(r.get("prior", [])):
            raise Error(
                "carry-forward requires every original source report in prior context"
            )
        if e["status"] == "excepted":
            raise Error("revision-specific owner exceptions cannot be carried forward")
        current_context = capture_findings(state, [fid])[fid]
        if r["finding_context"].get(fid) != current_context:
            raise Error(
                "finding disposition or sources changed after the review's captured input"
            )
        if not findings_ready(
            {"findings": {fid: f}}, e["head"], e["base"], confidential=confidential
        ):
            raise Error("unresolved finding cannot be carried forward")
        batch["findings"][fid] = current_context
    batch["id"] = digest(batch)
    batches = state.setdefault("carry_forwards", [])
    if batch not in batches:
        batches.append(batch)
    return batch


def carried(state, f, head, base):
    if state.get("version") != CHECKPOINT_VERSION:
        return False
    for batch in reversed(state.get("carry_forwards", [])):
        if batch.get("head") != head or batch.get("base") != base:
            continue
        evidence = batch.get("findings", {}).get(f["id"])
        if not evidence:
            continue
        if batch.get("id") != digest({k: v for k, v in batch.items() if k != "id"}):
            raise Error("carry-forward evidence changed")
        r = receipt(state, batch.get("receipt"))
        if r.get("policy_version") != POLICY_VERSION:
            raise Error(
                "carry-forward requires a policy 3 review with original source context"
            )
        validate_receipt(state, r)
        if (
            (r["commit"], r["base_sha"]) != (head, base)
            or f["id"] not in r.get("verifies", [])
            or not {source[0] for source in f["sources"]}.issubset(r.get("prior", []))
            or not batch.get("rationale", "").strip()
        ):
            raise Error(
                "carry-forward does not match the review's actual inputs/context"
            )
        if (
            evidence
            == r["finding_context"].get(f["id"])
            == capture_findings(state, [f["id"]])[f["id"]]
        ):
            return True
    return False


def findings_ready(state, head, base, check_exception=None, confidential=False):
    c = state.get("continuity", {})
    if (
        c.get("head") == head
        and c.get("base") == base
        and c.get("reviewed_head") != head
    ):
        validate_continuity(state, head, base, confidential=confidential)
        return findings_ready(
            state, c["reviewed_head"], base, check_exception, confidential
        )
    for f in state.get("findings", {}).values():
        # Reapply the same transition rules in CI; labels in JSON are not enough.
        scratch = {"findings": {f["id"]: {**f, "history": []}}}
        for event in f["history"]:
            seen = event.get("sources_seen", len(f["sources"]))
            if not isinstance(seen, int) or not 0 <= seen <= len(f["sources"]):
                raise Error("invalid finding observation history")
            scratch["findings"][f["id"]]["sources"] = f["sources"][:seen]
            disposition(
                scratch,
                f["id"],
                {
                    k: v
                    for k, v in event.items()
                    if k not in ("head", "base", "sources_seen")
                },
                event["head"],
                event["base"],
                confidential=confidential,
            )
        if not f["history"]:
            return False
        e = f["history"][-1]
        # A verification batch preserves the original disposition and states
        # exactly which reviewed revision it remains applicable to.
        if (e["head"] != head or e["base"] != base) and not carried(
            state, f, head, base
        ):
            return False
        if e.get("sources_seen", len(f["sources"])) != len(f["sources"]):
            return False
        if e["category"] == "unclassified" or e["status"] in (
            "investigate",
            "fixed-unverified",
        ):
            return False
        if e["status"] == "excepted":
            if e["head"] != head or e["base"] != base:
                return False
            if check_exception is not None:
                check_exception(f["id"], e["comment"], head, base)
        elif e["status"] not in ("verified", "refuted", "deferred"):
            return False
        if e["status"] == "deferred" and e["category"] not in (
            "nonblocking",
            "independent",
        ):
            return False
        if any(
            old["category"] in ("blocking", "concern") for old in f["history"]
        ) and e["category"] not in ("blocking", "concern"):
            return False
    return True


def approved(state, head, base, confidential=False):
    if any(r["status"] == "pending" for r in state.get("reviews", [])):
        return False
    if state.get("version") == 1:
        reviews = [
            r for r in state.get("reviews", []) if r["phase"] in ("code", "docs")
        ]
        return bool(
            reviews
            and reviews[-1].get("valid", True)
            and reviews[-1]["status"] == "completed"
            and reviews[-1]["outcome"] == "approve"
            and reviews[-1]["unresolved"] == 0
            and reviews[-1]["commit"] == head
            and reviews[-1]["base_sha"] == base
        )
    reviews = [r for r in state["reviews"] if r["phase"] in ("code", "docs")]
    if not reviews or reviews[-1]["status"] != "completed":
        return False
    r = reviews[-1]
    if (
        r.get("policy_version") not in (VERSION, POLICY_VERSION)
        or r["base_sha"] != base
    ):
        return False
    if r["commit"] != head:
        try:
            validate_continuity(state, head, base, confidential=confidential)
        except Error:
            return False
    validate_receipt(state, r)
    return findings_ready(state, head, base, confidential=confidential)


def continuity_source(state, r):
    return digest(
        {
            "receipt": r,
            "findings": state.get("findings", {}),
            "carry_forwards": state.get("carry_forwards", []),
        }
    )


def validate_continuity(state, head, base, confidential=False):
    """Check receipt binding; callers MUST independently recompute the Git proof.

    Git comparison belongs in the local and trusted-main boundary, not in this
    pure policy module. An arbitrary `proof` attestation alone is insufficient.
    """
    c = state.get("continuity", {})
    if state.get("version") != CHECKPOINT_VERSION or (c.get("head"), c.get("base")) != (
        head,
        base,
    ):
        raise Error("nonsemantic continuity missing or stale")
    r = receipt(state, c.get("receipt"))
    implementation = [x for x in state["reviews"] if x["phase"] in ("code", "docs")]
    proof = c.get("proof", {})
    if (
        not implementation
        or implementation[-1]["id"] != r["id"]
        or r["commit"] == head
        or (c.get("reviewed_head"), r["base_sha"]) != (r["commit"], base)
        or not all(
            re.fullmatch("[0-9a-f]{40,64}", value or "") for value in (head, base)
        )
        or proof.get("kind") != "license-headers"
        or (proof.get("from_head"), proof.get("head"), proof.get("base"))
        != (r["commit"], head, base)
        or c.get("source_digest") != continuity_source(state, r)
    ):
        raise Error("nonsemantic continuity does not bind the applicable review")
    if any(
        f.get("history") and f["history"][-1]["status"] == "excepted"
        for f in state.get("findings", {}).values()
    ):
        raise Error(
            "revision-specific owner exceptions cannot use nonsemantic continuity"
        )
    if not approved(state, r["commit"], base, confidential=confidential):
        raise Error("continuity source lacks applicable review and dispositions")
    return c


def record_continuity(state, ident, head, base, proof, confidential=False):
    r = receipt(state, ident)
    c = {
        "receipt": ident,
        "reviewed_head": r["commit"],
        "head": head,
        "base": base,
        "proof": copy.deepcopy(proof),
        "source_digest": continuity_source(state, r),
    }
    candidate = {**state, "continuity": c}
    validate_continuity(candidate, head, base, confidential=confidential)
    state["continuity"] = c
    return c


def integration_current(state, head, base, confidential=False):
    evidence = state.get("integration", {})
    if (evidence.get("head"), evidence.get("base"), evidence.get("merge_base")) != (
        head,
        base,
        base,
    ):
        raise Error("integration evidence missing or stale for current head/target")
    r = receipt(state, evidence.get("receipt"))
    implementation = [x for x in state["reviews"] if x["phase"] in ("code", "docs")]
    if (
        not implementation
        or r["id"] != implementation[-1]["id"]
        or r["phase"] not in ("code", "docs")
    ):
        raise Error(
            "integration must reference the applicable implementation review, not a plan"
        )
    if r["base_sha"] != base or not evidence.get("rationale", "").strip():
        raise Error("integration continuity does not cover these revisions")
    if r["commit"] != head:
        validate_continuity(state, head, base, confidential=confidential)
        if evidence.get("material_change"):
            raise Error(
                "material integration requires review of the actual current revision"
            )
    if evidence.get("material_change") and (r.get("scope") != "initial"):
        raise Error("material integration needs renewed initial review")
    if not approved(state, head, base, confidential=confidential):
        raise Error("integration lacks applicable review and finding dispositions")
