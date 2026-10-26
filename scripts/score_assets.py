#!/usr/bin/env python3
"""Calculate evidence-backed triage ranges from tagged JSON assets; never access assets."""
import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path


SCORING_VERSION = "1.0.0"
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
    priority, rule_id = classify(bounds, lower, upper, coverage, scope)
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
        "enrichment_mode": enrichment_mode,
        "execution_status": execution,
        "interpretation": "Heuristic review priority, not vulnerability confirmation or probability.",
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
    complete = sum(asset["triage"]["score_total"] is not None for asset in assets)
    return {
        "scoring_version": SCORING_VERSION,
        "summary": {
            "input_sha256": source_hash,
            "record_count": len(assets),
            "priority_counts": {code: counts[code] for code in PRIORITY_LABELS},
            "execution_status_counts": dict(executions),
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
