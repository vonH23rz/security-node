#!/usr/bin/env python3
"""Security Node Controller.

The Controller validates configuration before rendering any dashboard output.
Real scanner logic is not implemented yet.

This slice builds a small normalized internal state model from the validated
configuration and renders the dashboard from that model.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html as _html
import importlib.util
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml


STATUS_CLASS_BY_NAME = {
    "NOT VERIFIED": "status-not-verified",
    "VERIFIED": "status-verified",
    "UNEXPECTED": "status-unexpected",
    "ACCEPTED": "status-accepted",
    "UNKNOWN": "status-unknown",
}

CONFIDENCE_CLASS_BY_NAME = {
    "UNKNOWN": "confidence-unknown",
    "LOW": "confidence-low",
    "MEDIUM": "confidence-medium",
}

ALLOWED_SCANNER_RESULT_STATES = {
    "VERIFIED",
    "UNEXPECTED",
    "ACCEPTED",
    "UNKNOWN",
}

ALLOWED_SCANNER_RESULT_PROTOCOLS = {
    "tcp",
    "udp",
}

DEFAULT_SCANNER_EVIDENCE_MAX_AGE_MINUTES = 24 * 60
SCANNER_EVIDENCE_FUTURE_TOLERANCE_MINUTES = 5


def status_class(status: str) -> str:
    """Return the calm rendering class for a known status value."""

    return STATUS_CLASS_BY_NAME.get(status, "status-unknown")


def confidence_class(confidence: str) -> str:
    """Return the calm rendering class for a known confidence value."""

    return CONFIDENCE_CLASS_BY_NAME.get(confidence, "confidence-unknown")


@dataclass(frozen=True)
class ExpectedPort:
    """One expected host/port exposure from the validated config."""

    host_id: str
    host_display_name: str
    host_address: str
    network_id: str
    protocol: str
    port: int
    verification_status: str


@dataclass(frozen=True)
class ScannerResult:
    """One observed scanner result.

    This is only the model shape for future scanner output. The Controller does
    not collect live scanner results yet.
    """

    host_id: str
    host_address: str
    protocol: str
    port: int
    observed_state: str
    source: str
    checked_at: str


@dataclass(frozen=True)
class SecurityNodeState:
    """Normalized Controller state derived from a validated config file."""

    site_name: str
    controller_id: str
    controller_display_name: str
    controller_network: str
    controller_capabilities: tuple[str, ...]
    scanner_evidence_max_age_minutes: int
    network_count: int
    host_count: int
    probe_count: int
    accepted_risk_count: int
    external_exposure_expected_count: int
    expected_surface: tuple[ExpectedPort, ...]
    expected_surface_count: int
    expected_surface_not_verified_count: int
    observed_results: tuple[ScannerResult, ...]
    observed_result_count: int
    observed_result_unexpected_count: int
    verification_level: str
    security_confidence: str


def load_validator_module() -> ModuleType:
    """Load the validator script despite its CLI-friendly hyphenated filename."""

    validator_path = Path(__file__).with_name("validate-config.py")
    spec = importlib.util.spec_from_file_location("security_node_config_validator", validator_path)

    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load validator module from {validator_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def print_validation_report(config: Path, report: object) -> None:
    """Print validator output in the same clear style as the standalone validator."""

    errors = getattr(report, "errors", [])
    warnings = getattr(report, "warnings", [])

    print("Security Node Controller")
    print(f"config={config}")

    for warning in warnings:
        print(f"WARNING: {warning}")

    for error in errors:
        print(f"ERROR: {error}")

    print(f"summary: {len(errors)} error(s), {len(warnings)} warning(s)")


def load_validated_config(config: Path) -> dict[str, Any]:
    """Load YAML config after schema validation has already succeeded."""

    with config.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)

    if not isinstance(loaded, dict):
        raise ValueError("validated config did not load as a mapping")

    return loaded


def expected_surface_key(
    host_id: str,
    host_address: str,
    protocol: str,
    port: int,
) -> tuple[str, str, str, int]:
    """Return the stable comparison key for expected ports and evidence."""

    return (host_id, host_address, protocol.lower(), port)


def verified_expected_surface_keys(
    observed_results: tuple[ScannerResult, ...],
) -> set[tuple[str, str, str, int]]:
    """Return expected-surface keys with explicit VERIFIED evidence."""

    return {
        expected_surface_key(
            result.host_id,
            result.host_address,
            result.protocol,
            result.port,
        )
        for result in observed_results
        if result.observed_state == "VERIFIED"
    }


def configured_expected_surface_keys(
    config_data: dict[str, Any],
) -> set[tuple[str, str, str, int]]:
    """Return configured expected-surface keys without using evidence."""

    keys: set[tuple[str, str, str, int]] = set()

    for host in config_data.get("hosts", []):
        host_id = str(host["id"])
        host_address = str(host["address"])

        for port in host.get("expected_ports", []):
            keys.add(
                expected_surface_key(
                    host_id,
                    host_address,
                    "tcp",
                    int(port),
                )
            )

    return keys


def determine_security_confidence(
    expected_surface_count: int,
    expected_surface_not_verified_count: int,
    observed_result_unexpected_count: int,
) -> str:
    """Return calm confidence from current observed and expected posture.

    Unexpected observed exposure is evidence that the configured posture and
    observed posture do not match, so it takes priority and lowers confidence.
    A fully verified expected surface without unexpected observations earns
    MEDIUM confidence because this is still controller-side imported evidence,
    not an independent external proof.
    """

    if observed_result_unexpected_count > 0:
        return "LOW"

    if expected_surface_count > 0 and expected_surface_not_verified_count == 0:
        return "MEDIUM"

    return "UNKNOWN"


def classify_observed_results(
    config_data: dict[str, Any],
    observed_results: tuple[ScannerResult, ...],
) -> tuple[ScannerResult, ...]:
    """Classify observed evidence against the configured expected surface.

    Evidence for a non-configured surface item is unexpected. Configured
    surface evidence keeps its imported state unless later policy slices define
    more nuanced handling.
    """

    expected_keys = configured_expected_surface_keys(config_data)
    classified: list[ScannerResult] = []

    for result in observed_results:
        result_key = expected_surface_key(
            result.host_id,
            result.host_address,
            result.protocol,
            result.port,
        )
        observed_state = result.observed_state

        if result_key not in expected_keys:
            observed_state = "UNEXPECTED"

        classified.append(
            ScannerResult(
                host_id=result.host_id,
                host_address=result.host_address,
                protocol=result.protocol,
                port=result.port,
                observed_state=observed_state,
                source=result.source,
                checked_at=result.checked_at,
            )
        )

    return tuple(classified)


def build_expected_surface(
    config_data: dict[str, Any],
    observed_results: tuple[ScannerResult, ...] = (),
) -> tuple[ExpectedPort, ...]:
    """Build the expected host/port surface from validated host definitions.

    This is not scan output. It is the configured expectation matched against
    optional explicit scanner evidence. Without matching VERIFIED evidence,
    expected ports remain NOT VERIFIED.
    """

    expected: list[ExpectedPort] = []
    verified_keys = verified_expected_surface_keys(observed_results)

    for host in config_data.get("hosts", []):
        host_id = str(host["id"])
        host_display_name = str(host.get("display_name") or host_id)
        host_address = str(host["address"])
        network_id = str(host["network"])

        for port in host.get("expected_ports", []):
            protocol = "tcp"
            expected_key = expected_surface_key(
                host_id,
                host_address,
                protocol,
                int(port),
            )
            verification_status = "VERIFIED" if expected_key in verified_keys else "NOT VERIFIED"

            expected.append(
                ExpectedPort(
                    host_id=host_id,
                    host_display_name=host_display_name,
                    host_address=host_address,
                    network_id=network_id,
                    protocol=protocol,
                    port=int(port),
                    verification_status=verification_status,
                )
            )

    return tuple(expected)


def scanner_result_string_field(item: dict[str, Any], index: int, field: str) -> str:
    """Return a required non-empty string field from imported scanner evidence."""

    value = item[field]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"scanner result #{index + 1}: {field} must be a non-empty string")

    return value.strip()


def scanner_result_checked_at_field(item: dict[str, Any], index: int) -> tuple[str, datetime]:
    """Return a required ISO-8601 timestamp with timezone from scanner evidence."""

    checked_at = scanner_result_string_field(item, index, "checked_at")
    parse_value = checked_at[:-1] + "+00:00" if checked_at.endswith("Z") else checked_at

    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as error:
        raise ValueError(
            f"scanner result #{index + 1}: checked_at must be an ISO-8601 timestamp with timezone offset"
        ) from error

    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise ValueError(
            f"scanner result #{index + 1}: checked_at must be an ISO-8601 timestamp with timezone offset"
        )

    return checked_at, parsed


def validate_scanner_result_checked_at_freshness(
    checked_at: datetime,
    index: int,
    scanner_evidence_max_age_minutes: int,
    now: datetime,
) -> None:
    """Refuse impossible or stale scanner evidence timestamps."""

    checked_at_utc = checked_at.astimezone(_dt.timezone.utc)
    now_utc = now.astimezone(_dt.timezone.utc)

    if checked_at_utc > now_utc + _dt.timedelta(minutes=SCANNER_EVIDENCE_FUTURE_TOLERANCE_MINUTES):
        raise ValueError(
            f"scanner result #{index + 1}: checked_at must not be more than "
            f"{SCANNER_EVIDENCE_FUTURE_TOLERANCE_MINUTES} minutes in the future"
        )

    if checked_at_utc < now_utc - _dt.timedelta(minutes=scanner_evidence_max_age_minutes):
        raise ValueError(
            f"scanner result #{index + 1}: checked_at is older than scanner evidence "
            f"max age of {scanner_evidence_max_age_minutes} minutes"
        )


def scanner_evidence_max_age_minutes_from_config(config_data: dict[str, Any]) -> int:
    """Return configured scanner evidence freshness window in minutes."""

    controller = config_data.get("controller", {})
    return int(
        controller.get(
            "scanner_evidence_max_age_minutes",
            DEFAULT_SCANNER_EVIDENCE_MAX_AGE_MINUTES,
        )
    )


def load_scanner_results(
    scanner_results: Path | None,
    scanner_evidence_max_age_minutes: int = DEFAULT_SCANNER_EVIDENCE_MAX_AGE_MINUTES,
    now: datetime | None = None,
) -> tuple[ScannerResult, ...]:
    """Load optional scanner results from a YAML evidence file.

    This does not run a scanner. It only ingests explicit observed evidence
    produced elsewhere, so the Controller never invents verification results.
    """

    if scanner_results is None:
        return ()

    now = datetime.now(_dt.timezone.utc) if now is None else now

    with scanner_results.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)

    if loaded is None:
        return ()

    if not isinstance(loaded, list):
        raise ValueError("scanner results file must contain a YAML list")

    results: list[ScannerResult] = []
    required_fields = {
        "host_id",
        "host_address",
        "protocol",
        "port",
        "observed_state",
        "source",
        "checked_at",
    }
    seen_result_keys: set[tuple[str, str, str, int]] = set()

    for index, item in enumerate(loaded):
        if not isinstance(item, dict):
            raise ValueError(f"scanner result #{index + 1}: must be a mapping")

        missing = sorted(required_fields - set(item))
        if missing:
            raise ValueError(
                f"scanner result #{index + 1}: missing required field(s): {', '.join(missing)}"
            )

        host_id = scanner_result_string_field(item, index, "host_id")
        host_address = scanner_result_string_field(item, index, "host_address")
        protocol = scanner_result_string_field(item, index, "protocol").lower()
        observed_state = scanner_result_string_field(item, index, "observed_state").upper()
        source = scanner_result_string_field(item, index, "source")
        checked_at, checked_at_timestamp = scanner_result_checked_at_field(item, index)
        validate_scanner_result_checked_at_freshness(
            checked_at_timestamp,
            index,
            scanner_evidence_max_age_minutes,
            now,
        )

        port = item["port"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"scanner result #{index + 1}: port must be between 1 and 65535")

        if protocol not in ALLOWED_SCANNER_RESULT_PROTOCOLS:
            allowed = ", ".join(sorted(ALLOWED_SCANNER_RESULT_PROTOCOLS))
            raise ValueError(
                f"scanner result #{index + 1}: protocol must be one of: {allowed}"
            )

        if observed_state not in ALLOWED_SCANNER_RESULT_STATES:
            allowed = ", ".join(sorted(ALLOWED_SCANNER_RESULT_STATES))
            raise ValueError(
                f"scanner result #{index + 1}: observed_state must be one of: {allowed}"
            )

        result_key = expected_surface_key(host_id, host_address, protocol, port)
        if result_key in seen_result_keys:
            raise ValueError(
                f"scanner result #{index + 1}: duplicate scanner result for {host_id} {host_address} {protocol}/{port}"
            )
        seen_result_keys.add(result_key)

        results.append(
            ScannerResult(
                host_id=host_id,
                host_address=host_address,
                protocol=protocol,
                port=port,
                observed_state=observed_state,
                source=source,
                checked_at=checked_at,
            )
        )

    return tuple(results)


def build_state_model(
    config_data: dict[str, Any],
    observed_results: tuple[ScannerResult, ...] = (),
) -> SecurityNodeState:
    """Build the normalized Controller state model.

    This intentionally does not scan anything yet. It only turns a validated
    configuration file and optional explicit scanner evidence into stable
    Controller state for later scanner slices.
    """

    site = config_data["site"]
    controller = config_data["controller"]
    external_exposure = config_data["external_exposure"]
    scanner_evidence_max_age_minutes = scanner_evidence_max_age_minutes_from_config(config_data)
    classified_observed_results = classify_observed_results(config_data, observed_results)
    expected_surface = build_expected_surface(
        config_data,
        observed_results=classified_observed_results,
    )
    observed_result_unexpected_count = sum(
        1 for item in classified_observed_results if item.observed_state == "UNEXPECTED"
    )


    controller_id = str(controller["id"])
    controller_display_name = str(controller.get("display_name") or controller_id)
    capabilities = tuple(str(capability) for capability in controller.get("capabilities", []))

    expected_surface_count = len(expected_surface)
    expected_surface_not_verified_count = sum(
        1 for item in expected_surface if item.verification_status == "NOT VERIFIED"
    )

    return SecurityNodeState(
        site_name=str(site["name"]),
        controller_id=controller_id,
        controller_display_name=controller_display_name,
        controller_network=str(controller["network"]),
        controller_capabilities=capabilities,
        scanner_evidence_max_age_minutes=scanner_evidence_max_age_minutes,
        network_count=len(config_data.get("networks", [])),
        host_count=len(config_data.get("hosts", [])),
        probe_count=len(config_data.get("probes", [])),
        accepted_risk_count=len(config_data.get("accepted_risks", [])),
        external_exposure_expected_count=len(external_exposure.get("expected", [])),
        expected_surface=expected_surface,
        expected_surface_count=expected_surface_count,
        expected_surface_not_verified_count=expected_surface_not_verified_count,
        observed_results=classified_observed_results,
        observed_result_count=len(classified_observed_results),
        observed_result_unexpected_count=observed_result_unexpected_count,
        verification_level="Controller only",
        security_confidence=determine_security_confidence(
            expected_surface_count,
            expected_surface_not_verified_count,
            observed_result_unexpected_count,
        ),
    )


def render_confidence_badge(confidence: str) -> str:
    """Render a calm confidence badge.

    The value stays explicit and human-readable. The class gives the future GUI
    a stable hook for styling confidence separately from scanner/status badges.
    """

    escaped_confidence = _html.escape(confidence)
    escaped_class = _html.escape(confidence_class(confidence))
    return f'<span class="confidence-badge {escaped_class}">{escaped_confidence}</span>'


def render_status_badge(status: str) -> str:
    """Render a calm status badge.

    The status text stays explicit and human-readable. The class gives the
    future GUI a stable hook for color and layout without changing semantics.
    """

    escaped_status = _html.escape(status)
    escaped_class = _html.escape(status_class(status))
    return f'<span class="status {escaped_class}">{escaped_status}</span>'


def render_expected_surface_rows(state: SecurityNodeState) -> str:
    """Render expected verification surface rows."""

    if not state.expected_surface:
        return (
            "        <tr class=\"expected-surface-row expected-surface-empty\">"
            "<td class=\"expected-surface-cell expected-surface-empty-cell\" colspan=\"6\">"
            "No expected host ports configured."
            "</td></tr>"
        )

    rows = []
    for item in state.expected_surface:
        rows.append(
            "        <tr class=\"expected-surface-row\">"
            f"<td class=\"expected-surface-cell expected-surface-host\">{_html.escape(item.host_display_name)}</td>"
            f"<td class=\"expected-surface-cell expected-surface-address\">{_html.escape(item.host_address)}</td>"
            f"<td class=\"expected-surface-cell expected-surface-network\">{_html.escape(item.network_id)}</td>"
            f"<td class=\"expected-surface-cell expected-surface-protocol\">{_html.escape(item.protocol.upper())}</td>"
            f"<td class=\"expected-surface-cell expected-surface-port\">{item.port}</td>"
            f"<td class=\"expected-surface-cell expected-surface-status\">{render_status_badge(item.verification_status)}</td>"
            "</tr>"
        )

    return "\n".join(rows)


def render_observed_result_rows(state: SecurityNodeState) -> str:
    """Render observed scanner result rows.

    No rows are produced until scanner logic exists and provides evidence.
    """

    if not state.observed_results:
        return (
            "        <tr class=\"observed-result-row observed-result-empty\">"
            "<td class=\"observed-result-cell observed-result-empty-cell\" colspan=\"7\">"
            "No scanner results collected yet."
            "</td></tr>"
        )

    rows = []
    for item in state.observed_results:
        rows.append(
            "        <tr class=\"observed-result-row\">"
            f"<td class=\"observed-result-cell observed-result-host-id\">{_html.escape(item.host_id)}</td>"
            f"<td class=\"observed-result-cell observed-result-address\">{_html.escape(item.host_address)}</td>"
            f"<td class=\"observed-result-cell observed-result-protocol\">{_html.escape(item.protocol.upper())}</td>"
            f"<td class=\"observed-result-cell observed-result-port\">{item.port}</td>"
            f"<td class=\"observed-result-cell observed-result-state\">{render_status_badge(item.observed_state)}</td>"
            f"<td class=\"observed-result-cell observed-result-source\">{_html.escape(item.source)}</td>"
            f"<td class=\"observed-result-cell observed-result-checked-at\">{_html.escape(item.checked_at)}</td>"
            "</tr>"
        )

    return "\n".join(rows)


SECURITY_NODE_LOGO_DATA_URI = (
    "data:image/png;base64,"
    "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"
)


def render_dashboard(output: Path, state: SecurityNodeState) -> None:
    """Render the current dashboard from normalized Controller state."""

    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    capabilities = ", ".join(state.controller_capabilities) if state.controller_capabilities else "none"
    expected_surface_rows = render_expected_surface_rows(state)
    observed_result_rows = render_observed_result_rows(state)
    security_confidence_class = _html.escape(confidence_class(state.security_confidence))
    security_confidence_text = _html.escape(state.security_confidence)
    security_confidence_badge = render_confidence_badge(state.security_confidence)
    security_status_strip_class = _html.escape(
        f"status-strip-{confidence_class(state.security_confidence)}"
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Node</title>
  <link rel="icon" type="image/png" href="{SECURITY_NODE_LOGO_DATA_URI}">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --vonh-red: #ff4539;
      --vonh-blue: #9cc9ff;
      --vonh-green: #34c759;
      --vonh-indigo: #0a84ff;
      --vonh-grey: #b3b6b6;
      --vonh-background: #f3f5f7;
      --vonh-text: #53585f;
    }}

    .page-body {{
      color: #53585f;
      background: #f3f5f7;
      display: block;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 0.75rem;
    }}

    .page-main {{
      display: block;
      margin: 0 auto;
      max-width: 118rem;
      width: 100%;
    }}

    .page-header,
    .security-status-strip,
    .controller-state-section,
    .configuration-summary-section,
    .expected-surface-section,
    .observed-results-section,
    .page-footer {{
      background: #ffffff;
      border: 1px solid rgba(83, 88, 95, 0.16);
      border-radius: 0.85rem;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
      padding: 0.9rem 1rem;
    }}

    .page-header {{
      align-items: center;
      display: flex;
      gap: 1.25rem;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }}

    .page-brand {{
      align-items: center;
      display: flex;
      gap: 0.85rem;
      min-width: 0;
    }}

    .page-logo {{
      border-radius: 0.85rem;
      flex: 0 0 auto;
      height: 3.2rem;
      width: 3.2rem;
    }}

    .page-heading-group {{
      min-width: 0;
    }}

    .page-title {{
      line-height: 1.15;
      margin: 0;
    }}

    .page-subtitle {{
      color: rgba(83, 88, 95, 0.86);
      margin: 0.2rem 0 0;
    }}

    .page-header-meta {{
      align-items: center;
      display: grid;
      gap: 0.25rem 0.85rem;
      grid-template-columns: auto auto;
      text-align: right;
      white-space: nowrap;
    }}

    .page-header-meta-label {{
      color: rgba(83, 88, 95, 0.78);
      font-weight: 700;
    }}

    .page-meta {{
      margin: 0.35rem 0;
    }}

    .security-status-strip {{
      align-items: center;
      border-left: 0.4rem solid #b3b6b6;
      display: flex;
      gap: 1rem;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }}

    .status-strip-confidence-unknown {{
      border-left-color: #b3b6b6;
    }}

    .status-strip-confidence-low {{
      border-left-color: #ff4539;
    }}

    .status-strip-confidence-medium {{
      border-left-color: #9cc9ff;
    }}

    .security-status-strip .security-confidence {{
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin: 0;
    }}

    .status-strip-meta {{
      color: rgba(83, 88, 95, 0.78);
      display: flex;
      flex-wrap: wrap;
      gap: 0.85rem;
      justify-content: flex-end;
      text-align: right;
    }}

    .top-information-grid {{
      display: grid;
      gap: 0.75rem;
      grid-template-columns: minmax(24rem, 0.8fr) minmax(36rem, 1.2fr);
      margin-bottom: 0.75rem;
    }}

    .controller-state-heading,
    .configuration-summary-heading {{
      margin: 0 0 0.5rem;
    }}

    .controller-state-list {{
      display: grid;
      gap: 0.6rem;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      margin: 0;
    }}

    .controller-state-item {{
      background: rgba(179, 182, 182, 0.12);
      border: 1px solid rgba(83, 88, 95, 0.14);
      border-radius: 0.75rem;
      display: grid;
      gap: 0.25rem;
      padding: 0.65rem;
    }}

    .controller-state-term {{
      color: rgba(83, 88, 95, 0.78);
      font-size: 0.85rem;
      font-weight: 700;
      margin: 0;
    }}

    .controller-state-value {{
      margin: 0;
      min-height: 1.7rem;
    }}

    .posture-summary,
    .configuration-summary-list {{
      display: grid;
      gap: 0.6rem;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      list-style: none;
      margin: 0;
      padding-left: 0;
    }}

    .summary-metric,
    .configuration-summary-metric {{
      background: rgba(179, 182, 182, 0.12);
      border: 1px solid rgba(83, 88, 95, 0.14);
      border-radius: 0.75rem;
      margin: 0;
      padding: 0.65rem;
    }}

    .summary-metric-unexpected,
    .configuration-summary-metric-unexpected {{
      border-color: rgba(255, 69, 57, 0.32);
      font-weight: 700;
    }}

    .expected-surface-section,
    .observed-results-section {{
      margin-top: 0.75rem;
    }}

    .expected-surface-heading,
    .observed-results-heading {{
      margin: 0 0 0.5rem;
    }}

    .expected-surface-description,
    .observed-results-description {{
      margin: 0.35rem 0 0.75rem;
    }}

    .table-scroll {{
      overflow-x: auto;
    }}

    .expected-surface-table,
    .observed-results-table {{
      border-collapse: collapse;
      min-width: 42rem;
      width: 100%;
    }}

    .expected-surface-header-cell,
    .expected-surface-cell,
    .observed-results-header-cell,
    .observed-result-cell {{
      border-bottom: 1px solid rgba(83, 88, 95, 0.16);
      padding: 0.5rem 0.65rem;
      text-align: left;
      vertical-align: top;
    }}

    .expected-surface-header-cell,
    .observed-results-header-cell {{
      background: rgba(179, 182, 182, 0.18);
      font-weight: 700;
    }}

    .expected-surface-row:last-child .expected-surface-cell,
    .observed-result-row:last-child .observed-result-cell {{
      border-bottom: 0;
    }}

    .observed-result-empty-cell {{
      background: rgba(179, 182, 182, 0.10);
      color: rgba(83, 88, 95, 0.78);
      font-style: italic;
      text-align: center;
    }}

    .page-footer {{
      margin-top: 0.75rem;
    }}

    .scanner-implementation-notice,
    .generated-timestamp {{
      margin: 0.35rem 0;
    }}


    .status {{
      border: 1px solid currentColor;
      border-radius: 999px;
      display: inline-block;
      font-size: 0.85rem;
      font-weight: 700;
      line-height: 1;
      padding: 0.25rem 0.5rem;
      white-space: nowrap;
    }}

    .status-not-verified,
    .status-unknown {{
      background: #b3b6b6;
      color: #53585f;
      opacity: 1;
    }}

    .status-verified {{
      background: #34c759;
      color: #ffffff;
      opacity: 1;
    }}

    .status-accepted {{
      background: #0a84ff;
      color: #ffffff;
      opacity: 1;
    }}

    .status-unexpected {{
      background: #ff4539;
      color: #ffffff;
      font-weight: 800;
    }}

    .security-confidence {{
      font-weight: 700;
    }}

    .confidence-label {{
      margin-right: 0.35rem;
    }}

    .confidence-badge {{
      border: 1px solid currentColor;
      border-radius: 999px;
      display: inline-block;
      font-size: 0.85rem;
      font-weight: 700;
      line-height: 1;
      padding: 0.25rem 0.5rem;
      white-space: nowrap;
    }}

    .confidence-unknown {{
      background: #b3b6b6;
      color: #53585f;
      opacity: 1;
    }}

    .confidence-low {{
      background: #ff4539;
      color: #ffffff;
      font-weight: 800;
    }}

    .confidence-medium {{
      background: #9cc9ff;
      color: #53585f;
      opacity: 1;
    }}

    @media (max-width: 72rem) {{
      .top-information-grid {{
        grid-template-columns: 1fr;
      }}

      .configuration-summary-list {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
    }}

    @media (max-width: 56rem) {{
      .page-header,
      .security-status-strip {{
        align-items: flex-start;
        flex-direction: column;
      }}

      .page-header-meta {{
        text-align: left;
      }}

      .status-strip-meta {{
        justify-content: flex-start;
        text-align: left;
      }}

      .controller-state-list,
      .configuration-summary-list {{
        grid-template-columns: 1fr;
      }}
    }}

    @media (max-width: 48rem) {{
      .page-body {{
        padding: 0.75rem;
      }}

      .page-header,
      .security-status-strip,
      .controller-state-section,
      .configuration-summary-section,
      .expected-surface-section,
      .observed-results-section,
      .page-footer {{
        border-radius: 0.75rem;
        padding: 0.85rem;
      }}

      .expected-surface-header-cell,
      .expected-surface-cell,
      .observed-results-header-cell,
      .observed-result-cell {{
        font-size: 0.9rem;
        padding: 0.4rem 0.5rem;
      }}
    }}
  </style>
</head>
<body class="page-body">
  <main class="page-main">
    <header class="page-header">
      <div class="page-brand">
        <img class="page-logo" src="{SECURITY_NODE_LOGO_DATA_URI}" alt="" aria-hidden="true">
        <div class="page-heading-group">
          <h1 class="page-title">Security Node</h1>
          <p class="page-subtitle">Security posture dashboard</p>
        </div>
      </div>
      <div class="page-header-meta" aria-label="Security Node metadata">
        <div class="page-header-meta-label">Generated:</div><div>{now}</div>
        <div class="page-header-meta-label">Site:</div><div>{_html.escape(state.site_name)}</div>
        <div class="page-header-meta-label">Controller:</div><div>{_html.escape(state.controller_display_name)}</div>
      </div>
    </header>

    <section class="security-status-strip {security_status_strip_class}" aria-label="Security Node status summary">
      <p class="security-confidence {security_confidence_class}" aria-label="Security Confidence: {security_confidence_text}"><span class="confidence-label">Security Confidence:</span> {security_confidence_badge}</p>
      <div class="status-strip-meta">
        <span>Verification Level: {_html.escape(state.verification_level)}</span>
        <span>Expected Surface NOT VERIFIED: {state.expected_surface_not_verified_count}</span>
        <span>Observed Scanner Results UNEXPECTED: {state.observed_result_unexpected_count}</span>
        <span>Config schema validation passed before rendering.</span>
      </div>
    </section>

    <div class="top-information-grid">
      <section class="controller-state-section" aria-labelledby="controller-state">
        <h2 id="controller-state" class="controller-state-heading">Controller State</h2>
        <dl class="controller-state-list">
          <div class="controller-state-item controller-state-controller-id-item">
            <dt class="controller-state-term controller-state-controller-id-label">Controller ID</dt>
            <dd class="controller-state-value controller-state-controller-id">{_html.escape(state.controller_id)}</dd>
          </div>
          <div class="controller-state-item controller-state-display-name-item">
            <dt class="controller-state-term controller-state-display-name-label">Controller Display Name</dt>
            <dd class="controller-state-value controller-state-display-name">{_html.escape(state.controller_display_name)}</dd>
          </div>
          <div class="controller-state-item controller-state-network-item">
            <dt class="controller-state-term controller-state-network-label">Controller Network</dt>
            <dd class="controller-state-value controller-state-network">{_html.escape(state.controller_network)}</dd>
          </div>
          <div class="controller-state-item controller-state-capabilities-item">
            <dt class="controller-state-term controller-state-capabilities-label">Controller Capabilities</dt>
            <dd class="controller-state-value controller-state-capabilities">{_html.escape(capabilities)}</dd>
          </div>
          <div class="controller-state-item controller-state-scanner-evidence-max-age-item">
            <dt class="controller-state-term controller-state-scanner-evidence-max-age-label">Scanner Evidence Max Age</dt>
            <dd class="controller-state-value controller-state-scanner-evidence-max-age">{state.scanner_evidence_max_age_minutes} minutes</dd>
          </div>
        </dl>
      </section>

      <section class="configuration-summary-section" aria-labelledby="configuration-summary">
        <h2 id="configuration-summary" class="configuration-summary-heading">Configuration Summary</h2>
        <ul class="posture-summary configuration-summary-list">
          <li class="summary-metric summary-metric-networks configuration-summary-metric configuration-summary-metric-networks">Networks: {state.network_count}</li>
          <li class="summary-metric summary-metric-hosts configuration-summary-metric configuration-summary-metric-hosts">Hosts: {state.host_count}</li>
          <li class="summary-metric summary-metric-probes configuration-summary-metric configuration-summary-metric-probes">Probes: {state.probe_count}</li>
          <li class="summary-metric summary-metric-accepted-risks configuration-summary-metric configuration-summary-metric-accepted-risks">Accepted Risks: {state.accepted_risk_count}</li>
          <li class="summary-metric summary-metric-external-exposure configuration-summary-metric configuration-summary-metric-external-exposure">External Exposure Expectations: {state.external_exposure_expected_count}</li>
          <li class="summary-metric summary-metric-expected-surface configuration-summary-metric configuration-summary-metric-expected-surface">Expected Verification Surface Items: {state.expected_surface_count}</li>
          <li class="summary-metric summary-metric-expected-not-verified configuration-summary-metric configuration-summary-metric-expected-not-verified">Expected Surface NOT VERIFIED: {state.expected_surface_not_verified_count}</li>
          <li class="summary-metric summary-metric-observed-results configuration-summary-metric configuration-summary-metric-observed-results">Observed Scanner Results: {state.observed_result_count}</li>
          <li class="summary-metric summary-metric-unexpected configuration-summary-metric configuration-summary-metric-unexpected">Observed Scanner Results UNEXPECTED: {state.observed_result_unexpected_count}</li>
        </ul>
      </section>
    </div>

    <section class="expected-surface-section" aria-labelledby="expected-verification-surface">
      <h2 id="expected-verification-surface" class="expected-surface-heading">Expected Verification Surface</h2>
      <p class="expected-surface-description">Configured host ports that should be checked by future scanner logic.</p>
      <div class="table-scroll expected-surface-table-scroll">
        <table class="expected-surface-table">
          <thead>
          <tr class="expected-surface-header-row">
            <th class="expected-surface-header-cell expected-surface-header-host">Host</th>
            <th class="expected-surface-header-cell expected-surface-header-address">Address</th>
            <th class="expected-surface-header-cell expected-surface-header-network">Network</th>
            <th class="expected-surface-header-cell expected-surface-header-protocol">Protocol</th>
            <th class="expected-surface-header-cell expected-surface-header-port">Port</th>
            <th class="expected-surface-header-cell expected-surface-header-status">Status</th>
          </tr>
        </thead>
        <tbody>
{expected_surface_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section class="observed-results-section" aria-labelledby="observed-scanner-results">
      <h2 id="observed-scanner-results" class="observed-results-heading">Observed Scanner Results</h2>
      <p class="observed-results-description">Scanner result model is prepared, but live scanner logic is not implemented yet.</p>
      <div class="table-scroll observed-results-table-scroll">
        <table class="observed-results-table">
          <thead>
          <tr class="observed-results-header-row">
            <th class="observed-results-header-cell observed-results-header-host-id">Host ID</th>
            <th class="observed-results-header-cell observed-results-header-address">Address</th>
            <th class="observed-results-header-cell observed-results-header-protocol">Protocol</th>
            <th class="observed-results-header-cell observed-results-header-port">Port</th>
            <th class="observed-results-header-cell observed-results-header-state">Observed State</th>
            <th class="observed-results-header-cell observed-results-header-source">Source</th>
            <th class="observed-results-header-cell observed-results-header-checked-at">Checked At</th>
          </tr>
        </thead>
        <tbody>
{observed_result_rows}
          </tbody>
        </table>
      </div>
    </section>

    <footer class="page-footer">
      <p class="scanner-implementation-notice">Scanner logic is not implemented yet.</p>
      <p class="generated-timestamp">Generated: {now}</p>
    </footer>
  </main>
</body>
</html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Node Controller")
    parser.add_argument("--config", default="examples/config.example.yaml")
    parser.add_argument("--output", default="html/index.html")
    parser.add_argument(
        "--scanner-results",
        default=None,
        help="Optional YAML file containing observed scanner evidence. This does not run a scanner.",
    )
    args = parser.parse_args()

    config = Path(args.config)
    output = Path(args.output)
    scanner_results = Path(args.scanner_results) if args.scanner_results else None

    validator = load_validator_module()
    report = validator.validate_config(config)

    if not report.ok:
        print_validation_report(config, report)
        print("FAILED: refusing to render dashboard from invalid config")
        return 1

    print_validation_report(config, report)
    config_data = load_validated_config(config)

    try:
        observed_results = load_scanner_results(
            scanner_results,
            scanner_evidence_max_age_minutes=scanner_evidence_max_age_minutes_from_config(config_data),
        )
    except ValueError as error:
        print(f"ERROR: {error}")
        print("FAILED: refusing to render dashboard from invalid scanner results")
        return 1

    state = build_state_model(config_data, observed_results=observed_results)
    render_dashboard(output, state)
    print(f"Wrote dashboard from validated state model: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
