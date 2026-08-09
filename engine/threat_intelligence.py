from __future__ import annotations

import ipaddress
import math
import re
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")

URL_FIELDS = (
    "control_url",
    "download_url",
    "callback_url",
    "landing_url",
    "urls",
    "lt_urls",
    "sub_urls",
    "dynamic_nets",
)

RISK_TERMS = ("c2", "botnet", "malware", "phish", "fraud", "scam", "black", "risk", "trojan")
NETWORK_TEXT_FIELDS = set(URL_FIELDS) | {
    "control_mailbox",
    "control_phone",
    "domains",
    "top_domains",
    "domain",
    "top_domain",
    "ips",
    "ip",
    "threat_intel_records",
    "intelligence_records",
}


def analyze_threat_intelligence(sample: dict[str, Any]) -> dict[str, Any]:
    indicators = extract_network_indicators(sample)
    records = normalize_intelligence_records(sample.get("threat_intel_records") or sample.get("intelligence_records") or [])
    reputation = evaluate_reputation(indicators, records)
    graph = build_social_graph(sample, indicators, records)
    family = match_family_features(sample)
    summary = summarize_intelligence(reputation, graph, family)
    return {
        "indicators": indicators,
        "reputation": reputation,
        "social_graph": graph,
        "family_attribution": family,
        "summary": summary,
        "evidence_block": {
            "agent": "threat_intel",
            "claim": summary["claim"],
            "confidence": summary["confidence"],
            "score": summary["risk_score"],
            "evidence": summary["evidence"],
            "sources": summary["sources"],
            "missing_fields": summary["missing_fields"],
        },
    }


def extract_network_indicators(sample: dict[str, Any]) -> dict[str, list[str]]:
    domains: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()

    texts = []
    for key, value in sample.items():
        if key not in NETWORK_TEXT_FIELDS:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            text = str(item or "").strip()
            if not text:
                continue
            texts.append(text)
            if key in URL_FIELDS or text.startswith(("http://", "https://")):
                parsed = urlparse(text if "://" in text else f"https://{text}")
                if parsed.hostname:
                    urls.add(text)
                    add_host(parsed.hostname, domains, ips)

    joined = "\n".join(texts)
    for value in DOMAIN_RE.findall(joined):
        add_host(value, domains, ips)
    for value in IP_RE.findall(joined):
        add_host(value, domains, ips)
    emails.update(value.lower() for value in EMAIL_RE.findall(joined))
    phones.update(normalize_phone(value) for value in PHONE_RE.findall(joined))

    for key in ("domains", "top_domains"):
        for value in as_list(sample.get(key)):
            add_host(value, domains, ips)
    for key in ("ips",):
        for value in as_list(sample.get(key)):
            add_host(value, domains, ips)

    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips": sorted(ips),
        "emails": sorted(emails),
        "phones": sorted(value for value in phones if value),
    }


def add_host(value: str, domains: set[str], ips: set[str]) -> None:
    host = str(value).strip().lower().strip(".")
    if not host:
        return
    try:
        ip = ipaddress.ip_address(host)
        ips.add(str(ip))
    except ValueError:
        if DOMAIN_RE.fullmatch(host):
            domains.add(host)


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return digits[2:] if digits.startswith("86") and len(digits) == 13 else digits


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in re.split(r"[,;，；\n\r\t]+", str(value)) if item.strip()]


def normalize_intelligence_records(records: Any) -> list[dict[str, Any]]:
    if isinstance(records, dict):
        records = records.get("records", [])
    result = []
    for item in records if isinstance(records, list) else []:
        if not isinstance(item, dict):
            continue
        indicator = str(item.get("indicator") or item.get("value") or "").strip().lower()
        if not indicator:
            continue
        result.append(
            {
                "indicator": indicator,
                "type": str(item.get("type") or infer_indicator_type(indicator)),
                "source": str(item.get("source") or "local_intelligence"),
                "risk": normalize_risk(item.get("risk") or item.get("verdict")),
                "confidence": clamp01(item.get("confidence", 0.6)),
                "registered_by": str(item.get("registered_by") or item.get("registrant") or ""),
                "country": str(item.get("country") or ""),
                "region": str(item.get("region") or ""),
                "asn": str(item.get("asn") or ""),
                "organization": str(item.get("organization") or ""),
                "tags": as_list(item.get("tags")),
                "related": as_list(item.get("related")),
                "first_seen": str(item.get("first_seen") or ""),
                "last_seen": str(item.get("last_seen") or ""),
            }
        )
    return result


def infer_indicator_type(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.fullmatch(value):
        return "email"
    if PHONE_RE.fullmatch(value):
        return "phone"
    return "domain"


def normalize_risk(value: Any) -> float:
    text = str(value).strip().lower()
    labels = {
        "malicious": 1.0,
        "high": 0.9,
        "suspicious": 0.65,
        "medium": 0.55,
        "low": 0.25,
        "benign": 0.0,
        "clean": 0.0,
    }
    if text in labels:
        return labels[text]
    try:
        numeric = float(value)
        return max(0.0, min(1.0, numeric / 100 if numeric > 1 else numeric))
    except (TypeError, ValueError):
        return 0.4


def clamp01(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def evaluate_reputation(
    indicators: dict[str, list[str]],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    by_indicator: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_indicator[record["indicator"]].append(record)

    results = []
    all_indicators = [(kind[:-1], value) for kind in ("domains", "ips") for value in indicators[kind]]
    for kind, value in all_indicators:
        matched = by_indicator.get(value.lower(), [])
        layers = {
            "registration": [
                compact_record(item, ("source", "registered_by", "first_seen", "last_seen"))
                for item in matched
                if item["registered_by"] or item["first_seen"] or item["last_seen"]
            ],
            "attribution": [
                compact_record(item, ("source", "country", "region", "asn", "organization"))
                for item in matched
                if item["country"] or item["region"] or item["asn"] or item["organization"]
            ],
            "threat_history": [
                compact_record(item, ("source", "risk", "confidence", "tags"))
                for item in matched
                if item["tags"] or item["risk"] > 0
            ],
        }
        risk = weighted_record_risk(matched)
        if not matched and any(term in value for term in RISK_TERMS):
            risk = 0.55
        results.append(
            {
                "indicator": value,
                "type": kind,
                "risk_score": round(risk, 4),
                "reputation": reputation_label(risk),
                "layers": layers,
                "source_count": len({item["source"] for item in matched}),
                "data_status": "matched" if matched else "no_local_match",
            }
        )

    aggregate = max((item["risk_score"] for item in results), default=0.0)
    return {
        "items": results,
        "aggregate_risk": aggregate,
        "queried_layers": ["registration", "attribution", "threat_history"],
        "notice": "Results are based on supplied/local intelligence records; no external service was queried.",
    }


def compact_record(record: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: record[field] for field in fields if record.get(field) not in ("", [], None)}


def weighted_record_risk(records: list[dict[str, Any]]) -> float:
    if not records:
        return 0.0
    weighted = sum(item["risk"] * max(0.1, item["confidence"]) for item in records)
    weights = sum(max(0.1, item["confidence"]) for item in records)
    corroboration = min(0.15, max(0, len({item["source"] for item in records}) - 1) * 0.05)
    return min(1.0, weighted / weights + corroboration)


def reputation_label(score: float) -> str:
    if score >= 0.75:
        return "malicious"
    if score >= 0.45:
        return "suspicious"
    if score > 0:
        return "low_risk"
    return "unknown"


def build_social_graph(
    sample: dict[str, Any],
    indicators: dict[str, list[str]],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()

    def add_node(node_type: str, value: str, **attrs: Any) -> str:
        node_id = f"{node_type}:{value.lower()}"
        nodes.setdefault(node_id, {"id": node_id, "type": node_type, "value": value, **attrs})
        return node_id

    sample_id = add_node("app", str(sample.get("package_name") or sample.get("md5") or sample.get("sample_id") or "sample"))
    for kind in ("domains", "ips", "emails", "phones"):
        node_type = kind[:-1]
        for value in indicators[kind]:
            target = add_node(node_type, value)
            edges.add((sample_id, target, "observed_in"))

    for record in records:
        source = add_node(record["type"], record["indicator"], risk=record["risk"])
        for related in record["related"]:
            related_type = infer_indicator_type(related)
            target = add_node(related_type, related)
            edges.add((source, target, "threat_intel_related"))
        for field, node_type in (("registered_by", "registrant"), ("organization", "organization")):
            if record[field]:
                target = add_node(node_type, record[field])
                edges.add((source, target, field))

    node_degree: dict[str, int] = defaultdict(int)
    adjacency: dict[str, set[str]] = defaultdict(set)
    for source, target, _ in edges:
        node_degree[source] += 1
        node_degree[target] += 1
        adjacency[source].add(target)
        adjacency[target].add(source)

    clusters = connected_components(nodes, adjacency)
    shared_entities = [
        nodes[node_id]
        for node_id, degree in sorted(node_degree.items(), key=lambda item: item[1], reverse=True)
        if degree >= 2 and nodes[node_id]["type"] in {"email", "phone", "registrant", "organization", "domain"}
    ]
    return {
        "nodes": list(nodes.values()),
        "edges": [{"source": source, "target": target, "relation": relation} for source, target, relation in sorted(edges)],
        "clusters": clusters,
        "shared_entities": shared_entities[:20],
        "team_signals": {
            "shared_entity_count": len(shared_entities),
            "multi_app_cluster": any(cluster["app_count"] > 1 for cluster in clusters),
            "suspicious": len(shared_entities) >= 2,
        },
    }


def connected_components(nodes: dict[str, dict[str, Any]], adjacency: dict[str, set[str]]) -> list[dict[str, Any]]:
    visited = set()
    clusters = []
    for start in nodes:
        if start in visited:
            continue
        queue = deque([start])
        members = []
        visited.add(start)
        while queue:
            current = queue.popleft()
            members.append(current)
            for neighbor in adjacency.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        clusters.append(
            {
                "id": f"cluster-{len(clusters) + 1}",
                "members": members,
                "app_count": sum(1 for item in members if nodes[item]["type"] == "app"),
                "size": len(members),
            }
        )
    return clusters


def match_family_features(sample: dict[str, Any]) -> dict[str, Any]:
    sample_features = vectorize_sample(sample)
    family_library = sample.get("family_feature_library") or sample.get("threat_family_library") or []
    matches = []
    for family in family_library if isinstance(family_library, list) else []:
        if not isinstance(family, dict):
            continue
        family_features = vectorize_sample(family.get("features") or family)
        similarity, shared = feature_similarity(sample_features, family_features)
        matches.append(
            {
                "family": str(family.get("family") or family.get("name") or "unknown"),
                "similarity": round(similarity, 4),
                "mutation_relation": mutation_relation(similarity),
                "shared_features": shared[:20],
            }
        )
    matches.sort(key=lambda item: item["similarity"], reverse=True)
    best = matches[0] if matches else None
    return {
        "sample_vector": sorted(sample_features),
        "matches": matches[:10],
        "best_match": best,
        "attributed_family": best["family"] if best and best["similarity"] >= 0.55 else "",
        "mutation_relation": best["mutation_relation"] if best else "unknown",
    }


def vectorize_sample(sample: dict[str, Any]) -> set[str]:
    features = set()
    field_prefixes = {
        "permissions": "perm",
        "plugins": "sdk",
        "domains": "domain",
        "ips": "ip",
        "api_calls": "api",
        "native_libraries": "so",
        "certificates": "cert",
        "dynamic_behaviors": "behavior",
    }
    for field, prefix in field_prefixes.items():
        for value in as_list(sample.get(field)):
            features.add(f"{prefix}:{value.lower()}")
    for field, prefix in (
        ("packer", "packer"),
        ("signature_status", "signature"),
        ("fraud_family", "label"),
        ("virus_name", "label"),
        ("package_name", "package"),
    ):
        value = sample.get(field)
        if value not in ("", None, False):
            features.add(f"{prefix}:{str(value).lower()}")
    apk = sample.get("apk_analysis") if isinstance(sample.get("apk_analysis"), dict) else {}
    for item in apk.get("structure", {}).get("dex_files", []):
        for marker in item.get("suspicious_markers", []):
            features.add(f"dex:{marker}")
    for item in apk.get("structure", {}).get("native_libraries", []):
        if item.get("name"):
            features.add(f"so:{str(item['name']).lower()}")
    return features


def feature_similarity(left: set[str], right: set[str]) -> tuple[float, list[str]]:
    if not left or not right:
        return 0.0, []
    shared = sorted(left.intersection(right))
    jaccard = len(shared) / len(left.union(right))
    cosine = len(shared) / math.sqrt(len(left) * len(right))
    return 0.55 * cosine + 0.45 * jaccard, shared


def mutation_relation(similarity: float) -> str:
    if similarity >= 0.85:
        return "same_variant"
    if similarity >= 0.7:
        return "close_variant"
    if similarity >= 0.55:
        return "probable_mutation"
    if similarity >= 0.35:
        return "weak_relation"
    return "unrelated"


def summarize_intelligence(
    reputation: dict[str, Any],
    graph: dict[str, Any],
    family: dict[str, Any],
) -> dict[str, Any]:
    risk = reputation["aggregate_risk"]
    evidence = []
    sources = set()
    matched = [item for item in reputation["items"] if item["data_status"] == "matched"]
    if matched:
        evidence.append(f"{len(matched)} 个域名/IP命中本地情报记录。")
        for item in matched:
            for layer in item["layers"].values():
                sources.update(record.get("source", "") for record in layer if record.get("source"))
    if graph["team_signals"]["suspicious"]:
        evidence.append(f"关系图发现 {graph['team_signals']['shared_entity_count']} 个多边关联实体。")
        risk = max(risk, 0.65)
    best = family.get("best_match")
    if best and best["similarity"] >= 0.55:
        evidence.append(f"与黑产家族 {best['family']} 的特征相似度为 {best['similarity']:.2f}。")
        risk = max(risk, min(0.9, best["similarity"]))
    if not evidence:
        evidence.append("未在当前提供的本地情报记录和家族库中发现明确命中。")
    confidence = min(0.98, 0.35 + len(matched) * 0.12 + len(sources) * 0.08 + (0.15 if best else 0))
    return {
        "risk_score": round(risk, 4),
        "confidence": round(confidence, 4),
        "claim": f"情报溯源风险{risk_label(risk)}",
        "evidence": evidence,
        "sources": sorted(sources),
        "missing_fields": [
            field
            for field, missing in (
                ("threat_intel_records", not matched),
                ("family_feature_library", not family.get("matches")),
            )
            if missing
        ],
    }


def risk_label(score: float) -> str:
    if score >= 0.75:
        return "较高"
    if score >= 0.45:
        return "中等"
    return "较低"
