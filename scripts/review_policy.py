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
    if state["version"] == VERSION:
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


def authorization(state, phase, round_):
    return next(
        (
            a
            for a in state.get("authorizations", [])
            if a["phase"] == phase and a["round"] == round_
        ),
        None,
    )


def budget(state, phase):
    if any(r["status"] == "pending" for r in state.get("reviews", [])):
        raise Error("pending review: recover it before another invocation")
    round_ = count(state, phase) + 1
    ceiling = state.get("ceilings", {}).get(phase)
    if ceiling and round_ > ceiling["round"]:
        raise Error(
            f"{phase} scoped allowance exhausted at round {ceiling['round']}; owner decision required"
        )
    if round_ > {"docs": 1, "plan": 2, "code": 3}[phase] and not authorization(
        state, phase, round_
    ):
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
    """Historical policy stays historical; every new receipt uses policy 2."""
    ids = [r["id"] for r in state["reviews"]]
    if len(ids) != len(set(ids)):
        raise Error("duplicate review attempt IDs")
    historical = state.get("migration", {}).get("history", {})
    if not set(historical).issubset(ids):
        raise Error("migration lost review history")
    for ident, expected in historical.items():
        if digest(next(r for r in state["reviews"] if r["id"] == ident)) != expected:
            raise Error("historical attempt was rewritten")
    if state.get("version") == VERSION:
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
            if policy not in (1, VERSION):
                raise Error("unknown review policy")
            if (
                state.get("version") == VERSION
                and policy == 1
                and historical.get(r["id"]) != digest(r)
            ):
                raise Error("legacy review changed or was added after migration")
            limit = {"docs": 1, "plan": 2, "code": 5 if policy == 1 else 3}[phase]
            if r["round"] > limit:
                a = authorization(state, phase, r["round"])
                if not a:
                    raise Error("review budget exceeded without owner authorization")
                check_auth(phase, r["round"], a["comment"], "authorize")
            if policy == VERSION:
                validate_receipt(state, r)
        ceiling = state.get("ceilings", {}).get(phase)
        if ceiling:
            check_auth(phase, ceiling["round"], ceiling["comment"], "ceiling")
            if len(done) > ceiling["round"]:
                raise Error("scoped review allowance exceeded")
    # A retry grant names the exact failures preceding an invocation. Reusing
    # a comment cannot silently expand it to cover a newly failed attempt.
    prefix = []
    for r in state["reviews"]:
        failed_ids, consecutive = failed_attempts({"reviews": prefix}, r["phase"])
        if r.get("policy_version") == VERSION and consecutive >= 2:
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
    prior_ids = r.get("prior", [])
    if r["scope"] != "initial" and (
        not prior_ids or not r.get("rationale", "").strip()
    ):
        raise Error("focused scope needs prior receipts and continuity rationale")
    before = state["reviews"][: state["reviews"].index(r)]
    for ident in prior_ids:
        if ident not in [p["id"] for p in before]:
            raise Error("prior receipt must precede this review")
        p = receipt(state, ident)
        if p["phase"] != r["phase"]:
            raise Error("prior receipt has another phase")
        if r["scope"] == "follow-up" and p["base_sha"] != r["base_sha"]:
            raise Error("target changed; use integration or renewed initial scope")
    if r.get("material_change") and r["scope"] != "initial":
        raise Error("material change requires initial review")


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


def findings_ready(state, head, base, check_exception=None, confidential=False):
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
        # Every resolution is tied to actual inputs. A focused reviewer may carry
        # it forward only through a new explicit disposition for those inputs.
        if e["head"] != head or e["base"] != base:
            return False
        if e["category"] == "unclassified" or e["status"] in (
            "investigate",
            "fixed-unverified",
        ):
            return False
        if e["status"] == "excepted":
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
        r.get("policy_version") != VERSION
        or r["commit"] != head
        or r["base_sha"] != base
    ):
        return False
    validate_receipt(state, r)
    return findings_ready(state, head, base, confidential=confidential)


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
    if (
        r["commit"] != head
        or r["base_sha"] != base
        or not evidence.get("rationale", "").strip()
    ):
        raise Error("integration continuity does not cover these revisions")
    if evidence.get("material_change") and (r.get("scope") != "initial"):
        raise Error("material integration needs renewed initial review")
    if not approved(state, head, base, confidential=confidential):
        raise Error("integration lacks applicable review and finding dispositions")
