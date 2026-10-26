#!/usr/bin/env python3
"""Plan ordinary entry observations from a CSV; no network access or risk ranking."""
import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import tempfile
from collections import Counter, defaultdict, deque
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


TITLE_BUCKETS = ("generic_or_repeated", "other_nonempty", "empty", "error_hint")
ERROR_TITLE = re.compile(
    r"(?i)^\s*(?:[345]\d\d(?:\b|:)|HTTP\s+Status\s+[45]\d\d\b|"
    r"access\s+denied\b|forbidden\b|not\s+found\b|bad\s+gateway\b|"
    r"gateway\s+time|service\s+unavailable\b|invalid\s+url\b|object\s+moved\b|WAF(?:\b|拦截|阻断))"
)
URL_FIELDS = ("link", "url", "target", "网址", "host", "hostname", "domain", "域名", "ip")
NONWEB_PROTOCOLS = {
    "tls", "ssl", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "ssh", "ftp",
    "ftps", "sftp", "redis", "mongodb", "mysql", "postgres", "postgresql", "rdp", "sip",
    "quic", "adobe-crossdomain", "dns", "tcp", "udp",
}


def normalized_key(value):
    return str(value).strip().lstrip("\ufeff").casefold()


def title_key(value):
    return " ".join(str(value or "").split()).casefold()


def field(fields, names):
    for name in names:
        value = fields.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def port_value(value):
    if not value:
        return None
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError("invalid_port_field")
    return int(value)


def canonical_web_entry(fields):
    """Return (entry, disposition, reason); preserve protocol/path/query/fragment identity."""
    target = field(fields, URL_FIELDS)
    declared_protocol = field(fields, ("protocol", "scheme", "协议")).casefold()
    raw_port = field(fields, ("port", "端口"))
    try:
        supplied_port = port_value(raw_port)
    except ValueError as exc:
        return None, "invalid", str(exc)
    if not target:
        return None, "invalid", "missing_target"
    if re.search(r"[\s\x00-\x1f\x7f\\]", target):
        return None, "invalid", "invalid_url_characters"
    if "://" not in target:
        if declared_protocol in NONWEB_PROTOCOLS:
            return None, "nonweb", "declared_non_http_protocol"
        if declared_protocol not in ("http", "https"):
            return None, "invalid", "missing_http_scheme_or_protocol"
        try:
            if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address):
                target = "[" + target + "]"
        except ValueError:
            pass
        target = declared_protocol + "://" + target
    try:
        parts = urlsplit(target)
        scheme = parts.scheme.casefold()
        if scheme not in ("http", "https"):
            return None, "nonweb", "explicit_non_http_scheme"
        if not parts.hostname or parts.username is not None or parts.password is not None:
            return None, "invalid", "invalid_hostname_or_url_userinfo"
        hostname = parts.hostname.encode("idna").decode("ascii").casefold()
        if re.search(r"[\s\x00-\x1f\x7f/#?]", hostname):
            return None, "invalid", "invalid_hostname"
        explicit_port = parts.port
        if explicit_port is not None and not 1 <= explicit_port <= 65535:
            return None, "invalid", "invalid_url_port"
        if explicit_port is not None and supplied_port is not None and explicit_port != supplied_port:
            return None, "invalid", "conflicting_url_and_port_field"
        default_port = 443 if scheme == "https" else 80
        port = explicit_port or supplied_port or default_port
        netloc = "[" + hostname + "]" if ":" in hostname else hostname
        if port != default_port:
            netloc += ":" + str(port)
        path = parts.path or "/"
        url = urlunsplit((scheme, netloc, path, parts.query, parts.fragment))
        identity = (scheme, hostname, port, path, parts.query, parts.fragment)
        warnings = []
        if declared_protocol and declared_protocol != scheme:
            warnings.append("declared_protocol_differs_from_explicit_url")
        return {
            "url": url, "hostname": hostname, "protocol": scheme, "port": port,
            "path": path, "query": parts.query, "fragment": parts.fragment,
            "identity": identity, "normalization_warnings": warnings,
        }, "web", None
    except (ValueError, UnicodeError):
        return None, "invalid", "invalid_http_url"


def read_csv(source):
    raw = source.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
        encoding = "utf-8-sig"
    except UnicodeDecodeError:
        text = raw.decode("gb18030")
        encoding = "gb18030"
    try:
        dialect = csv.Sniffer().sniff(text[:65536], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    csv.field_size_limit(20_000_000)
    reader = csv.reader(io.StringIO(text, newline=""), dialect=dialect, strict=True)
    headers = next(reader, None)
    if not headers:
        raise ValueError("CSV requires a nonempty header row")
    canonical_headers = [normalized_key(name) for name in headers]
    if any(not name for name in canonical_headers) or len(set(canonical_headers)) != len(headers):
        raise ValueError("CSV has empty or duplicate normalized headers")
    if not set(canonical_headers).intersection(URL_FIELDS):
        raise ValueError("CSV has no recognized URL, host, domain or IP column")
    source_sha = hashlib.sha256(raw).hexdigest()
    records = []
    previous_line = reader.line_num
    for index, values in enumerate(reader, 1):
        start_line, end_line = previous_line + 1, reader.line_num
        previous_line = end_line
        if len(values) > len(headers):
            raise ValueError("CSV record " + str(index) + " has extra fields; check delimiter and quoting")
        warnings = []
        if len(values) < len(headers):
            warnings.append("missing_cells")
        padded = values + [None] * (len(headers) - len(values))
        original = dict(zip(headers, padded))
        records.append({
            "record_id": source_sha[:12] + ":r" + str(index),
            "csv_record": index, "source_row_start": start_line, "source_row_end": end_line,
            "fields": original, "input_warnings": warnings,
            "normalized_fields": dict(zip(canonical_headers, padded)),
        })
    return records, {"path": str(source), "sha256": source_sha, "encoding": encoding, "columns": headers}


def seed_hostname(value):
    value = value.strip()
    if not value or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ValueError("seed-host must be a hostname or absolute HTTP(S) URL")
    try:
        parts = urlsplit(value if "://" in value else "//" + value)
        if parts.username is not None or parts.password is not None or not parts.hostname:
            raise ValueError("invalid seed-host")
        if parts.scheme and parts.scheme.casefold() not in ("http", "https"):
            raise ValueError("seed URLs must use HTTP(S)")
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError("invalid seed-host port")
        return parts.hostname.encode("idna").decode("ascii").casefold()
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid seed-host; no target was constructed") from exc


def entry_order(candidate):
    scheme = candidate["protocol"]
    return (
        0 if scheme == "https" else 1,
        0 if candidate["port"] == (443 if scheme == "https" else 80) else 1,
        candidate["port"], candidate["path"], candidate["query"], candidate["fragment"],
        candidate["candidate_id"],
    )


def make_plan(records, source_info, budget, seed_hosts, generic_titles):
    by_identity = {}
    invalid, nonweb = [], []
    for record in records:
        fields = record.pop("normalized_fields")
        entry, disposition, reason = canonical_web_entry(fields)
        if disposition != "web":
            item = {**record, "reason": reason, "observation_stage": "inventory_only"}
            (invalid if disposition == "invalid" else nonweb).append(item)
            continue
        identity = entry.pop("identity")
        candidate = by_identity.get(identity)
        if candidate is None:
            digest = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()[:20]
            candidate = {
                "candidate_id": "entry-" + digest, **entry,
                "source_rows": [], "source_records": [], "ip_variants": [], "title_variants": [],
                "selected": False, "selection_reason": "deferred_by_budget",
                "observation_stage": "inventory_only", "next_action": "ordinary_entry_observation",
            }
            by_identity[identity] = candidate
        candidate["source_rows"].append(record["source_row_start"])
        candidate["source_records"].append(record)
        for name, value in (("ip_variants", field(fields, ("ip", "ip地址"))), ("title_variants", field(fields, ("title", "标题", "网站标题")))):
            if value not in candidate[name]:
                candidate[name].append(value)
        candidate["normalization_warnings"] = sorted(set(candidate["normalization_warnings"] + entry["normalization_warnings"]))
    candidates = sorted(by_identity.values(), key=lambda item: item["candidate_id"])
    if len({item["candidate_id"] for item in candidates}) != len(candidates):
        raise ValueError("Candidate identity collision; no output published")
    title_hosts = defaultdict(set)
    for candidate in candidates:
        for title in candidate["title_variants"]:
            if title_key(title):
                title_hosts[title_key(title)].add(candidate["hostname"])
    repeated = {title for title, hosts in title_hosts.items() if len(hosts) >= 5} | generic_titles
    for candidate in candidates:
        titles = candidate["title_variants"]
        useful = [title for title in titles if title_key(title) and not ERROR_TITLE.search(title)]
        if any(title_key(title) in repeated for title in useful):
            bucket = "generic_or_repeated"
        elif useful:
            bucket = "other_nonempty"
        elif any(title_key(title) for title in titles):
            bucket = "error_hint"
        else:
            bucket = "empty"
        candidate["title_bucket"] = bucket
    host_queues = defaultdict(list)
    for candidate in candidates:
        host_queues[candidate["hostname"]].append(candidate)
    queues = {host: deque(sorted(items, key=entry_order)) for host, items in host_queues.items()}
    matched_seeds = sorted(set(seed_hosts).intersection(queues))
    unmatched_seeds = sorted(set(seed_hosts) - set(queues))
    selected = []
    round_number = 0
    while len(selected) < budget and any(queues.values()):
        round_number += 1
        used_hosts = set()
        for host in matched_seeds:
            if queues[host] and len(selected) < budget:
                item = queues[host].popleft()
                item["selected"] = True
                item["selection_reason"] = "user_seed_coverage_round_" + str(round_number)
                selected.append(item)
                used_hosts.add(host)
        bucket_hosts = defaultdict(deque)
        for host in sorted(queues, key=lambda value: hashlib.sha256(value.encode()).hexdigest()):
            if queues[host] and host not in used_hosts:
                bucket_hosts[queues[host][0]["title_bucket"]].append(host)
        while len(selected) < budget and any(bucket_hosts.values()):
            for bucket in TITLE_BUCKETS:
                if len(selected) >= budget:
                    break
                if not bucket_hosts[bucket]:
                    continue
                host = bucket_hosts[bucket].popleft()
                item = queues[host].popleft()
                item["selected"] = True
                item["selection_reason"] = "stratified_host_round_" + str(round_number) + ":" + bucket
                selected.append(item)
    selected_ids = {item["candidate_id"] for item in selected}
    remaining = [item["candidate_id"] for item in candidates if item["candidate_id"] not in selected_ids]
    source_mapped = sum(len(item["source_records"]) for item in candidates)
    if source_mapped + len(invalid) + len(nonweb) != len(records):
        raise ValueError("Source-record reconciliation failed")
    bucket_counts = Counter(item["title_bucket"] for item in candidates)
    selected_counts = Counter(item["title_bucket"] for item in selected)
    seed_matches = [{
        "hostname": host,
        "matched_candidate_ids": [item["candidate_id"] for item in host_queues[host]],
        "selected_candidate_ids": [item["candidate_id"] for item in selected if item["hostname"] == host],
        "deferred_candidate_ids": [item["candidate_id"] for item in host_queues[host] if not item["selected"]],
    } for host in matched_seeds]
    selected_keys = ("candidate_id", "hostname", "url", "protocol", "port", "source_rows", "title_bucket", "selection_reason", "observation_stage", "next_action")
    return {
        "planner_version": "1.0.0", "is_risk_ranking": False, "source": source_info,
        "summary": {
            "original_records": len(records), "candidate_count": len(candidates),
            "candidate_mapped_records": source_mapped, "invalid_record_count": len(invalid),
            "nonweb_record_count": len(nonweb), "selected_count": len(selected),
            "unselected_count": len(remaining), "budget": budget, "budget_unit": "starting_web_entries",
            "actual_visits": 0, "planned_is_not_visited": True, "is_risk_ranking": False,
            "title_buckets": {bucket: {"candidates": bucket_counts[bucket], "selected": selected_counts[bucket], "unselected": bucket_counts[bucket]-selected_counts[bucket]} for bucket in TITLE_BUCKETS},
            "seed_matches": seed_matches, "unmatched_seed_hosts": unmatched_seeds,
            "grouping_note": "Exact normalized entry identity only. Shared titles/IPs do not establish one application; all address and source variants remain evidence inputs.",
            "selection_note": "Each host gets at most one entry per coverage round; seeds go first and use existing HTTPS entries preferentially. This is observation coverage, not vulnerability priority.",
            "privacy_note": "This local plan includes original URLs and source data; do not share without reviewing sensitive parameters.",
        },
        "selected_plan": [{key: item[key] for key in selected_keys} for item in selected],
        "remaining_candidate_ids": remaining, "candidates": candidates,
        "invalid_records": invalid, "nonweb_records": nonweb,
    }


def publish_fresh(output, value):
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Existing CSV asset list; no network requests are made")
    parser.add_argument("--output", required=True, type=Path, help="Fresh local JSON plan; may contain sensitive source data")
    parser.add_argument("--budget", type=int, default=60, help="Number of starting Web entries to plan, not requests or completed visits")
    parser.add_argument("--seed-host", action="append", default=[], help="Existing hostname to cover first; never constructs a missing target")
    parser.add_argument("--generic-title", action="append", default=[], help="Exact normalized title used as an additional generic/repeated sampling label")
    args = parser.parse_args()
    source, output = args.input.resolve(), args.output.resolve()
    if args.budget < 0:
        parser.error("budget must be nonnegative")
    if source == output:
        parser.error("Output must not overwrite the input")
    if output.exists():
        parser.error("Output exists; choose a fresh path")
    try:
        seeds = [seed_hostname(value) for value in args.seed_host]
        records, source_info = read_csv(source)
        result = make_plan(records, source_info, args.budget, seeds, {title_key(value) for value in args.generic_title if title_key(value)})
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        parser.exit(1, "Planning failed: " + str(exc) + "\n")
    try:
        publish_fresh(output, result)
    except (OSError, ValueError):
        parser.exit(1, "Could not publish plan; choose a fresh writable output path.\n")
    summary = result["summary"]
    print(json.dumps({"original_records": summary["original_records"], "candidate_count": summary["candidate_count"], "selected_count": summary["selected_count"], "unselected_count": summary["unselected_count"], "invalid_record_count": summary["invalid_record_count"], "nonweb_record_count": summary["nonweb_record_count"], "is_risk_ranking": False, "output": str(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
