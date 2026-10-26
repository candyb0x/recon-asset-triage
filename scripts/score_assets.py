#!/usr/bin/env python3
"""Calculate evidence-backed triage ranges from tagged JSON assets; never access assets."""
import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path


SCORING_VERSION = "1.2.0"
LEVELS = {
    "A": (0, 5, 10, 15, 20),
    "T": (0, 5, 10, 20, 30, 40),
    "D": (0, 5, 10, 15, 20),
    "X": (0, 5, 10, 15, 20),
}
PRIORITY_LABELS = {
    "P1": "高优先级脆弱候选",
    "P2": "中优先级待验证",
    "P3": "低优先级常规",
    "P4": "信息不足待补充",
    "EXCLUDED": "明确超范围排除",
}
SCOPES = {"in_scope", "unknown", "out_of_scope"}
ENRICHMENT_MODES = {"offline", "authorized_read_only", "unspecified"}
TECHNICAL_LOWER_LIMITS = {
    "unspecified": 5,
    "surface_hint": 5,
    "assessed_no_signal": 0,
    "service_observed": 10,
    "lifecycle_confirmed": 10,
    "debug_observed": 10,
    "advisory_candidate": 20,
    "prerequisites_supported": 30,
    "verified_finding": 40,
}
ADVISORY_BASES = {"lifecycle_confirmed", "advisory_candidate", "prerequisites_supported"}
ACCESS_STATES = {
    "unknown", "error_only", "auth_wall", "public_content", "public_function",
    "authenticated_function", "nonweb_service", "render_pending", "render_failed", "transport_error",
}
OBSERVATION_STAGES = {
    "inventory_only", "http_observed", "browser_rendered", "function_mapped",
    "service_observed", "auth_blocked", "client_error", "browser_failed",
}
REVIEW_EVIDENCE_STAGES = {"http_observed", "browser_rendered", "function_mapped", "service_observed"}
AUTH_GROUP_BASES = {"unknown", "user_reported", "observed", "documented"}
QUEUE_REASONS = {
    "excluded": "Explicit scope exclusion; this asset is outside the review queue.",
    "existing_finding_review": "Review the existing finding report and applicability before planning further work.",
    "preauth_lead_review": "Supported pre-authentication signal warrants a bounded lead review.",
    "advisory_applicability_review": "Review advisory applicability and prerequisites before selecting live verification.",
    "authenticated_surface_mapping": "Roles are provided but post-authentication functions have not been observed.",
    "shared_auth_review": "Review the explicit group's representative authentication gate; retain each application separately.",
    "role_required": "A suitable authorized role or session must be provided before application review.",
    "authenticated_app_review": "Observed post-authentication functions and provided roles support application review.",
    "anonymous_app_review": "Observed public functions support anonymous application-boundary review.",
    "nonweb_service_review": "Observed non-web service context supports a scoped service review.",
    "availability_recheck": "Access errors require an availability recheck, not a low-risk conclusion.",
    "routine_observation": "Only public content is currently evidenced; retain routine observation and change triggers.",
    "entry_evidence": "Entry-point evidence is insufficient to select a current application review target.",
    "browser_evidence": "HTTP evidence is incomplete or JavaScript-dependent; render the page before judging functions.",
    "browser_tool_review": "Browser observation failed; retain the unresolved application and diagnose the evidence gap.",
    "client_transport_review": "The client or transport failed; this does not establish that the target has no service.",
}
LIVE_REVIEW_QUEUES = {
    "preauth_lead_review", "authenticated_app_review", "anonymous_app_review", "nonweb_service_review",
}
PENDING_OBSERVATION_QUEUES = {
    "entry_evidence", "browser_evidence", "browser_tool_review", "client_transport_review",
    "authenticated_surface_mapping", "role_required", "shared_auth_review", "availability_recheck",
}


def reject_constant(_value):
    raise ValueError("Non-finite numbers are not valid JSON input")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object keys are not permitted")
        result[key] = value
    return result


def dimension_range(value, dimension):
    levels = LEVELS[dimension]
    if value is None:
        return {"min": 0, "max": levels[-1]}
    if type(value) is int:
        lower = upper = value
    elif isinstance(value, dict) and set(value) == {"min", "max"}:
        lower, upper = value["min"], value["max"]
    else:
        raise ValueError("Scores must be an integer level, null, or a min/max object")
    if type(lower) is not int or type(upper) is not int:
        raise ValueError("Score bounds must be integer levels; booleans are not scores")
    if lower not in levels or upper not in levels or lower > upper:
        raise ValueError("Score level is outside the allowed dimension levels, or the interval is reversed")
    return {"min": lower, "max": upper}


def string_ids(value, label):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(label + " must be an array of nonempty strings")
    return list(value)


def technical_basis(asset, technical_minimum, technical_refs):
    basis = asset.get("technical_basis", {})
    if not isinstance(basis, dict) or set(basis) - {"kind", "evidence_refs", "advisory_refs"}:
        raise ValueError("technical_basis must contain only kind, evidence_refs and advisory_refs")
    kind = basis.get("kind", "unspecified")
    if not isinstance(kind, str) or kind not in TECHNICAL_LOWER_LIMITS:
        raise ValueError("technical_basis.kind is not a supported evidence category")
    evidence = string_ids(basis.get("evidence_refs", []), "technical_basis.evidence_refs")
    advisories = string_ids(basis.get("advisory_refs", []), "technical_basis.advisory_refs")
    if technical_minimum > TECHNICAL_LOWER_LIMITS[kind]:
        raise ValueError("Technical score lower bound exceeds the supplied evidence category")
    if technical_minimum >= 10 and (not evidence or not set(evidence).issubset(technical_refs)):
        raise ValueError("T lower bounds of 10 or more need explicit basis evidence included in evidence_refs.T")
    if kind in ADVISORY_BASES and (not advisories or not set(advisories).issubset(evidence)):
        raise ValueError("This technical basis needs advisory_refs included in its evidence_refs")
    return kind


def access_context(asset):
    context = asset.get("access_context", {})
    allowed = {"state", "evidence_refs", "available_roles", "auth_group_id", "auth_group_basis", "preauth_signal_refs"}
    if not isinstance(context, dict) or set(context) - allowed:
        raise ValueError("access_context contains unsupported fields or is not an object")
    state = context.get("state", "unknown")
    if not isinstance(state, str) or state not in ACCESS_STATES:
        raise ValueError("access_context.state is not a supported observation state")
    evidence = string_ids(context.get("evidence_refs", []), "access_context.evidence_refs")
    roles = string_ids(context.get("available_roles", []), "access_context.available_roles")
    preauth = string_ids(context.get("preauth_signal_refs", []), "access_context.preauth_signal_refs")
    if state != "unknown" and not evidence:
        raise ValueError("Observed access states need nonempty access_context.evidence_refs")
    group_id = context.get("auth_group_id")
    if group_id is not None and (not isinstance(group_id, str) or not group_id.strip()):
        raise ValueError("auth_group_id must be null or a nonempty string")
    group_basis = context.get("auth_group_basis", "unknown")
    if not isinstance(group_basis, str) or group_basis not in AUTH_GROUP_BASES:
        raise ValueError("auth_group_basis must be unknown, user_reported, observed or documented")
    if group_id is not None and (group_basis == "unknown" or not evidence):
        raise ValueError("An explicit authentication group needs a stated basis and access evidence")
    return {
        "state": state,
        "evidence_refs": evidence,
        "available_roles": roles,
        "auth_group_id": group_id,
        "auth_group_basis": group_basis,
        "preauth_signal_refs": preauth,
    }


def observation_stage(asset):
    stage = asset.get("observation_stage", "inventory_only")
    if not isinstance(stage, str) or stage not in OBSERVATION_STAGES:
        raise ValueError("observation_stage is not a supported evidence stage")
    refs = string_ids(asset.get("observation_refs", []), "observation_refs")
    browser_refs = string_ids(asset.get("browser_evidence_refs", []), "browser_evidence_refs")
    function_refs = string_ids(asset.get("function_evidence_refs", []), "function_evidence_refs")
    if stage != "inventory_only" and not refs:
        raise ValueError("Non-inventory observation stages need observation_refs")
    if stage == "browser_rendered" and not browser_refs:
        raise ValueError("browser_rendered needs browser_evidence_refs, not just an HTTP body")
    if stage == "function_mapped" and not function_refs:
        raise ValueError("function_mapped needs specific function_evidence_refs")
    return stage


def action_queue(scope, kind, technical_minimum, context, stage):
    state = context["state"]
    roles = context["available_roles"]
    if scope == "out_of_scope":
        return "excluded"
    if technical_minimum == 40 and kind == "verified_finding":
        return "existing_finding_review"
    if technical_minimum >= 20:
        return "preauth_lead_review" if context["preauth_signal_refs"] else "advisory_applicability_review"
    if state == "render_pending":
        return "browser_evidence"
    if state == "render_failed" or stage == "browser_failed":
        return "browser_tool_review"
    if state == "transport_error" or stage == "client_error":
        return "client_transport_review"
    if stage == "inventory_only":
        return "entry_evidence"
    if state == "auth_wall":
        if roles:
            return "authenticated_surface_mapping"
        return "shared_auth_review" if context["auth_group_id"] is not None else "role_required"
    if state == "authenticated_function":
        return "authenticated_app_review" if roles else "role_required"
    return {
        "public_function": "anonymous_app_review",
        "nonweb_service": "nonweb_service_review",
        "error_only": "availability_recheck",
        "public_content": "routine_observation",
    }.get(state, "entry_evidence")


def authentication_groups(assets):
    groups = {}
    for asset in assets:
        context = asset["triage"]["access_context"]
        group_id = context["auth_group_id"]
        if group_id is None:
            continue
        group = groups.setdefault(group_id, {"member_ids": [], "auth_wall_member_ids": [], "basis_levels": set()})
        group["member_ids"].append(asset["asset_id"])
        group["basis_levels"].add(context["auth_group_basis"])
        if context["state"] == "auth_wall":
            group["auth_wall_member_ids"].append(asset["asset_id"])
    return [
        {
            "auth_group_id": group_id,
            "member_ids": sorted(group["member_ids"]),
            "auth_wall_member_ids": sorted(group["auth_wall_member_ids"]),
            "basis_levels": sorted(group["basis_levels"]),
            "representative_auth_gate": min(group["auth_wall_member_ids"]) if group["auth_wall_member_ids"] else None,
        }
        for group_id, group in sorted(groups.items())
    ]


def classify(bounds, lower, upper, coverage, scope):
    if scope == "out_of_scope":
        return "EXCLUDED", "R0_SCOPE_EXCLUDED"
    if bounds["T"]["min"] == 40 and bounds["A"]["min"] >= 15:
        return "P1", "R1_T40_A15"
    if lower >= 60 and bounds["T"]["min"] >= 20:
        return "P1", "R2_L60_T20"
    if lower >= 30 or bounds["T"]["min"] >= 10:
        return "P2", "R3_L30_OR_T10"
    if (
        upper < 30
        and coverage >= 70
        and bounds["T"]["min"] == bounds["T"]["max"]
        and bounds["X"]["min"] == bounds["X"]["max"]
    ):
        return "P3", "R4_U30_C70_TX_EXACT"
    return "P4", "R5_INSUFFICIENT"


def triage_asset(asset, index, seen_ids):
    if not isinstance(asset, dict):
        raise ValueError("Each asset record must be an object")
    identifier = asset.get("asset_id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("asset_id must be a nonempty string")
    normalized_id = identifier.strip()
    if normalized_id in seen_ids:
        raise ValueError("asset_id must be unique, including after surrounding whitespace is removed")
    seen_ids.add(normalized_id)
    if "triage" in asset:
        raise ValueError("The reserved triage field already exists; score the original tagged input")
    scores = asset.get("scores", {})
    refs = asset.get("evidence_refs", {})
    if not isinstance(scores, dict) or set(scores) - set(LEVELS):
        raise ValueError("scores must be an object containing only A, T, D and X")
    if not isinstance(refs, dict) or set(refs) - set(LEVELS):
        raise ValueError("evidence_refs must be a dimension-to-ID-array object")
    for values in refs.values():
        if not isinstance(values, list) or any(not isinstance(ref, str) or not ref.strip() for ref in values):
            raise ValueError("Each evidence_refs entry must be an array of nonempty string IDs")
    scope = asset.get("scope_status", "unknown")
    if not isinstance(scope, str) or scope not in SCOPES:
        raise ValueError("scope_status must be in_scope, unknown or out_of_scope")
    enrichment_mode = asset.get("enrichment_mode", "unspecified")
    if not isinstance(enrichment_mode, str) or enrichment_mode not in ENRICHMENT_MODES:
        raise ValueError("enrichment_mode must be offline, authorized_read_only or unspecified")

    bounds, missing, partial = {}, [], []
    coverage = 0
    for dimension, levels in LEVELS.items():
        interval = dimension_range(scores.get(dimension), dimension)
        bounds[dimension] = interval
        cap = levels[-1]
        fully_unknown = interval == {"min": 0, "max": cap}
        if not fully_unknown and not refs.get(dimension):
            raise ValueError("Every constrained or exact dimension, including zero, needs an evidence reference")
        if fully_unknown:
            missing.append(dimension)
        elif interval["min"] != interval["max"]:
            partial.append(dimension)
        if interval["min"] == interval["max"]:
            coverage += cap
    lower = sum(value["min"] for value in bounds.values())
    upper = sum(value["max"] for value in bounds.values())
    kind = technical_basis(asset, bounds["T"]["min"], set(refs.get("T", [])))
    context = access_context(asset)
    stage = observation_stage(asset)
    if kind == "service_observed" and context["state"] == "auth_wall":
        raise ValueError("An authentication wall alone cannot establish an observed operational service")
    priority, rule_id = classify(bounds, lower, upper, coverage, scope)
    queue = action_queue(scope, kind, bounds["T"]["min"], context, stage)
    if scope == "out_of_scope":
        execution = "excluded"
    elif scope == "unknown":
        execution = "hold_scope_confirmation"
    else:
        execution = {
            "offline": "offline_analysis_only",
            "authorized_read_only": "read_only_enrichment_allowed",
            "unspecified": "review_plan_only",
        }[enrichment_mode]
    result = dict(asset)
    result["triage"] = {
        "priority": priority,
        "priority_label": PRIORITY_LABELS[priority],
        "rule_id": rule_id,
        "score_total": lower if lower == upper else None,
        "score_interval": {"min": lower, "max": upper},
        "dimension_ranges": bounds,
        "coverage_percent": coverage,
        "missing_dimensions": missing,
        "partial_dimensions": partial,
        "technical_basis_kind": kind,
        "access_context": context,
        "observation_stage": stage,
        "action_queue": queue,
        "queue_reason": QUEUE_REASONS[queue],
        "evidence_collection_allowed": scope == "in_scope" and enrichment_mode == "authorized_read_only",
        "ready_for_live_review": scope == "in_scope" and enrichment_mode == "authorized_read_only" and queue in LIVE_REVIEW_QUEUES and stage in REVIEW_EVIDENCE_STAGES,
        "enrichment_mode": enrichment_mode,
        "execution_status": execution,
        "interpretation": "Technical-signal triage, not a vulnerability probability or a gate on authorized evidence collection. P4 can still have mapped functions worth application review.",
    }
    return result


def score_inventory(records, source_hash):
    if not isinstance(records, list):
        raise ValueError("Input must be a JSON array of tagged asset objects")
    assets, seen_ids = [], set()
    for index, asset in enumerate(records, 1):
        try:
            assets.append(triage_asset(asset, index, seen_ids))
        except ValueError as exc:
            raise ValueError(f"Record {index}: {exc}") from exc
    counts = Counter(asset["triage"]["priority"] for asset in assets)
    executions = Counter(asset["triage"]["execution_status"] for asset in assets)
    queues = Counter(asset["triage"]["action_queue"] for asset in assets)
    stages = Counter(asset["triage"]["observation_stage"] for asset in assets)
    active = [asset for asset in assets if asset["triage"]["priority"] != "EXCLUDED"]
    pending = sum(
        asset["triage"]["observation_stage"] in {"inventory_only", "client_error", "browser_failed"}
        or asset["triage"]["action_queue"] in PENDING_OBSERVATION_QUEUES
        for asset in active
    )
    evidence_stage = (
        "no_active_records" if not active
        else "inventory_only" if all(asset["triage"]["observation_stage"] == "inventory_only" for asset in active)
        else "partial_evidence" if pending else "evidence_available"
    )
    complete = sum(asset["triage"]["score_total"] is not None for asset in assets)
    return {
        "scoring_version": SCORING_VERSION,
        "summary": {
            "input_sha256": source_hash,
            "record_count": len(assets),
            "priority_counts": {code: counts[code] for code in PRIORITY_LABELS},
            "execution_status_counts": dict(executions),
            "action_queue_counts": {queue: queues[queue] for queue in QUEUE_REASONS},
            "evidence_stage_counts": {stage: stages[stage] for stage in sorted(OBSERVATION_STAGES)},
            "pending_observation_records": pending,
            "assessment_stage": evidence_stage,
            "evidence_collection_allowed_count": sum(asset["triage"]["evidence_collection_allowed"] for asset in assets),
            "ready_for_live_review_count": sum(asset["triage"]["ready_for_live_review"] for asset in assets),
            "auth_groups": authentication_groups(assets),
            "complete_score_records": complete,
            "interval_score_records": len(assets) - complete,
            "note": "All input records and their order are retained. Scope-excluded records are outside the review queue.",
        },
        "assets": assets,
    }


def publish_fresh(output, result):
    content = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        # Link publishes a complete file atomically and cannot replace an existing path.
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON array of assets with A/T/D/X scores and evidence_refs")
    parser.add_argument("--output", required=True, type=Path, help="Fresh JSON output; existing files are protected")
    args = parser.parse_args()
    source, output = args.input.resolve(), args.output.resolve()
    if source == output:
        parser.error("Output must not overwrite the input")
    if output.exists():
        parser.error("Output exists; choose a fresh path")
    try:
        raw = source.read_bytes()
        records = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object, parse_constant=reject_constant)
        result = score_inventory(records, hashlib.sha256(raw).hexdigest())
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"Input validation failed: {exc}\n")
    try:
        publish_fresh(output, result)
    except (OSError, ValueError):
        parser.exit(1, "Could not publish output; choose a fresh writable output path.\n")
    print(json.dumps({"scoring_version": SCORING_VERSION, "record_count": result["summary"]["record_count"], "priority_counts": result["summary"]["priority_counts"], "output": str(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
