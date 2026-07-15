from __future__ import annotations

from dataclasses import dataclass
import socket
from typing import Any

from system_sentinel.geoip import choose_geoip_database_path, geoip_country_code


@dataclass(frozen=True)
class ConnectionIntentEnrichment:
    reverse_dns: str | None
    asn_organization: str | None
    geoip_country: str | None


@dataclass(frozen=True)
class ConnectionIntentClassification:
    category: str
    confidence: float
    recommended_action: str
    reasons: list[str]
    enrichment: ConnectionIntentEnrichment


def classify_connection_intent(
    *,
    ip_address: str,
    protocol: str,
    attempts: int,
    distinct_ports: int,
    recurrence_count: int,
    observed_ports: list[int],
    config: dict[str, Any],
) -> ConnectionIntentClassification:
    attempts_cfg = _as_dict(config.get("attempts_per_ip"))
    ports_cfg = _as_dict(config.get("distinct_destination_ports"))
    recurrence_cfg = _as_dict(config.get("recurrence_over_time"))
    sensitivity_cfg = _as_dict(config.get("protocol_port_sensitivity"))
    score_cfg = _as_dict(config.get("score_thresholds"))
    enrichment_cfg = _as_dict(config.get("ip_enrichment"))

    suspicious_attempts = _int_or(attempts_cfg.get("suspicious"), 3)
    likely_attempts = _int_or(attempts_cfg.get("likely_access_attempt"), 8)
    suspicious_ports = _int_or(ports_cfg.get("suspicious"), 2)
    likely_ports = _int_or(ports_cfg.get("likely_access_attempt"), 4)
    suspicious_recurrence = _int_or(recurrence_cfg.get("suspicious"), 3)
    likely_recurrence = _int_or(recurrence_cfg.get("likely_access_attempt"), 7)
    sensitive_weight = _int_or(sensitivity_cfg.get("weight"), 2)
    sensitive_ports = _int_list(sensitivity_cfg.get("sensitive_ports"), default=[22, 3389, 5900])
    suspicious_score = _int_or(score_cfg.get("suspicious"), 3)
    likely_score = _int_or(score_cfg.get("likely_access_attempt"), 6)

    score = 0
    reasons: list[str] = []

    if attempts >= likely_attempts:
        score += 3
        reasons.append("high_attempt_volume")
    elif attempts >= suspicious_attempts:
        score += 1
        reasons.append("elevated_attempt_volume")

    if distinct_ports >= likely_ports:
        score += 2
        reasons.append("broad_multi_port_targeting")
    elif distinct_ports >= suspicious_ports:
        score += 1
        reasons.append("multi_port_targeting")

    if recurrence_count >= likely_recurrence:
        score += 2
        reasons.append("high_recurrence_over_time")
    elif recurrence_count >= suspicious_recurrence:
        score += 1
        reasons.append("recurring_activity")

    sensitive_target = any(port in set(sensitive_ports) for port in observed_ports)
    if sensitive_target:
        score += max(1, sensitive_weight)
        reasons.append("sensitive_port_targeted")
    if protocol.lower() != "tcp":
        score += 1
        reasons.append("non_tcp_protocol_observed")

    if score >= likely_score:
        category = "likely_access_attempt"
        recommended_action = "block"
        confidence = min(0.99, 0.75 + (score - likely_score) * 0.03)
    elif score >= suspicious_score:
        category = "suspicious"
        recommended_action = "watch"
        confidence = min(0.89, 0.55 + (score - suspicious_score) * 0.05)
    else:
        category = "background_scan"
        recommended_action = "ignore"
        confidence = min(0.69, 0.35 + score * 0.05)
        if not reasons:
            reasons.append("low_signal_background_activity")

    enrichment = _enrich_ip(
        ip_address,
        enrichment_cfg,
        geoip_database_path=str(config.get("geoip_database_path", "")).strip(),
    )
    return ConnectionIntentClassification(
        category=category,
        confidence=round(confidence, 2),
        recommended_action=recommended_action,
        reasons=reasons,
        enrichment=enrichment,
    )


def _enrich_ip(
    ip_address: str, cfg: dict[str, Any], *, geoip_database_path: str
) -> ConnectionIntentEnrichment:
    if not bool(cfg.get("enabled", False)):
        return ConnectionIntentEnrichment(
            reverse_dns=None,
            asn_organization=None,
            geoip_country=None,
        )

    reverse_dns = _reverse_dns(ip_address) if bool(cfg.get("enable_reverse_dns", True)) else None
    asn_org = _asn_org(ip_address) if bool(cfg.get("enable_asn_lookup", True)) else None
    effective_geoip_path = choose_geoip_database_path(
        cfg.get("geoip_database_path"),
        geoip_database_path,
    )
    geoip_country = (
        geoip_country_code(ip_address, effective_geoip_path)
        if bool(cfg.get("enable_geoip", True))
        else None
    )
    return ConnectionIntentEnrichment(
        reverse_dns=reverse_dns,
        asn_organization=asn_org,
        geoip_country=geoip_country,
    )


def _reverse_dns(ip_address: str) -> str | None:
    try:
        host, _aliases, _addrlist = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror, OSError):
        return None
    return host or None


def _asn_org(ip_address: str) -> str | None:
    try:
        from ipwhois import IPWhois  # type: ignore[import-not-found]
    except ImportError:
        return None

    try:
        result = IPWhois(ip_address).lookup_rdap(depth=1)
    except (ValueError, OSError):
        return None
    network = result.get("network")
    if not isinstance(network, dict):
        return None
    name = network.get("name")
    return str(name) if isinstance(name, str) and name.strip() else None


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_or(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return default


def _int_list(value: object, *, default: list[int]) -> list[int]:
    if not isinstance(value, list):
        return default
    parsed = [int(v) for v in value if isinstance(v, int)]
    return parsed or default
