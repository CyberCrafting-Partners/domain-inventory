"""Shared VirusTotal API v3 parsing and persistent quota helpers."""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


VIRUSTOTAL_FIELDS = [
    "DomaineRacine",
    "DomaineAnalyse",
    "SourceDecouverte",
    "StatutRequete",
    "ReputationCommunaute",
    "Malicieux",
    "Suspect",
    "Inoffensif",
    "NonDetecte",
    "Timeout",
    "TotalMoteurs",
    "Verdict",
    "DerniereAnalyseUTC",
    "Categories",
    "Source",
]

JsonRequest = Callable[[str, str], tuple[Any | None, dict[str, str], int | None]]
DomainNormalizer = Callable[[str], str | None]


def _integer(value: Any) -> int:
    """Return a non-negative integer for a VirusTotal statistic."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _timestamp_utc(value: Any) -> str:
    """Convert a Unix timestamp to an ISO 8601 UTC timestamp."""
    try:
        timestamp = int(value)
        if timestamp < 0:
            return ""
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _verdict(stats: dict[str, Any], malicious_threshold: int) -> str:
    """Classify vendor signals without claiming that they prove maliciousness."""
    malicious = _integer(stats.get("malicious"))
    suspicious = _integer(stats.get("suspicious"))
    total = sum(_integer(value) for value in stats.values())
    if malicious >= malicious_threshold:
        return "SignaleMalveillant"
    if suspicious > 0 or malicious > 0:
        return "SignaleSuspect"
    if total > 0:
        return "AucunSignalementMalveillantOuSuspect"
    return "NonEvalue"


def domain_object_row(
    root_domain: str,
    item: dict[str, Any],
    discovery_source: str,
    normalize_domain: DomainNormalizer,
    malicious_threshold: int,
) -> dict[str, Any] | None:
    """Normalize one VirusTotal domain object into the project CSV schema."""
    if not isinstance(item, dict):
        return None
    name = normalize_domain(str(item.get("id") or ""))
    if not name or not (name == root_domain or name.endswith(f".{root_domain}")):
        return None
    attributes = item.get("attributes") or {}
    if not isinstance(attributes, dict):
        attributes = {}
    stats = attributes.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        stats = {}
    categories = attributes.get("categories") or {}
    if isinstance(categories, dict):
        category_text = " ; ".join(
            f"{provider}: {value}"
            for provider, value in sorted(categories.items())
            if value
        )
    else:
        category_text = ""
    counts = {
        "malicious": _integer(stats.get("malicious")),
        "suspicious": _integer(stats.get("suspicious")),
        "harmless": _integer(stats.get("harmless")),
        "undetected": _integer(stats.get("undetected")),
        "timeout": _integer(stats.get("timeout")),
    }
    reputation = attributes.get("reputation")
    return {
        "DomaineRacine": root_domain,
        "DomaineAnalyse": name,
        "SourceDecouverte": discovery_source,
        "StatutRequete": "Trouve",
        "ReputationCommunaute": "" if reputation is None else str(reputation),
        "Malicieux": counts["malicious"],
        "Suspect": counts["suspicious"],
        "Inoffensif": counts["harmless"],
        "NonDetecte": counts["undetected"],
        "Timeout": counts["timeout"],
        "TotalMoteurs": sum(counts.values()),
        "Verdict": _verdict(stats, malicious_threshold),
        "DerniereAnalyseUTC": _timestamp_utc(attributes.get("last_analysis_date")),
        "Categories": category_text,
        "Source": "VirusTotal API v3",
    }


def missing_domain_row(
    root_domain: str, domain: str, discovery_source: str
) -> dict[str, Any]:
    """Represent a domain that VirusTotal does not currently know."""
    row = {field: "" for field in VIRUSTOTAL_FIELDS}
    row.update(
        {
            "DomaineRacine": root_domain,
            "DomaineAnalyse": domain,
            "SourceDecouverte": discovery_source,
            "StatutRequete": "NonTrouve",
            "Verdict": "NonEvalue",
            "Source": "VirusTotal API v3",
        }
    )
    return row


def get_domain_report(
    root_domain: str,
    domain: str,
    discovery_source: str,
    request_json: JsonRequest,
    normalize_domain: DomainNormalizer,
    malicious_threshold: int,
) -> tuple[dict[str, Any] | None, int | None]:
    """Retrieve and normalize one existing VirusTotal domain report."""
    url = "https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(
        domain, safe=""
    )
    data, _, status = request_json(url, "VirusTotal domain report")
    if status == 404:
        return missing_domain_row(root_domain, domain, discovery_source), status
    item = data.get("data") if isinstance(data, dict) else None
    row = domain_object_row(
        root_domain,
        item if isinstance(item, dict) else {},
        discovery_source,
        normalize_domain,
        malicious_threshold,
    )
    return row, (422 if status == 200 and row is None else status)


def get_subdomains_page(
    root_domain: str,
    cursor: str,
    limit: int,
    request_json: JsonRequest,
    normalize_domain: DomainNormalizer,
    malicious_threshold: int,
) -> tuple[set[str], list[dict[str, Any]], str, int | None]:
    """Retrieve one page of direct subdomains and their existing VT reports."""
    parameters: dict[str, Any] = {"limit": limit}
    if cursor:
        parameters["cursor"] = cursor
    url = (
        "https://www.virustotal.com/api/v3/domains/"
        + urllib.parse.quote(root_domain, safe="")
        + "/subdomains?"
        + urllib.parse.urlencode(parameters)
    )
    data, _, status = request_json(url, "VirusTotal subdomains relationship")
    items = data.get("data") if isinstance(data, dict) else None
    invalid_success_response = status == 200 and not isinstance(items, list)
    if not isinstance(items, list):
        items = []
    names: set[str] = set()
    rows: list[dict[str, Any]] = []
    for item in items:
        row = domain_object_row(
            root_domain,
            item if isinstance(item, dict) else {},
            "VirusTotal subdomains",
            normalize_domain,
            malicious_threshold,
        )
        if row:
            names.add(str(row["DomaineAnalyse"]))
            rows.append(row)
    meta = data.get("meta") if isinstance(data, dict) else None
    next_cursor = str(meta.get("cursor") or "").strip() if isinstance(meta, dict) else ""
    if not next_cursor and isinstance(data, dict):
        links = data.get("links") or {}
        next_url = links.get("next") if isinstance(links, dict) else ""
        if next_url:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(str(next_url)).query)
            next_cursor = str((query.get("cursor") or [""])[0]).strip()
    return names, rows, next_cursor, (422 if invalid_success_response else status)


def load_daily_usage(state_file: Path, reported_today_count: int) -> int:
    """Load the highest known request count for the current UTC day."""
    today_utc = datetime.now(timezone.utc).date().isoformat()
    local_count = 0
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if state.get("date_utc") == today_utc:
            local_count = max(0, int(state.get("requests_attempted", 0)))
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return max(local_count, reported_today_count)


def save_daily_usage(state_file: Path, count: int, daily_quota: int, plan: str) -> None:
    """Atomically persist request attempts without keys or queried domains."""
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_file.with_suffix(state_file.suffix + ".tmp")
    payload = {
        "date_utc": datetime.now(timezone.utc).date().isoformat(),
        "plan": plan,
        "requests_attempted": count,
        "configured_daily_quota": daily_quota,
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(state_file)
