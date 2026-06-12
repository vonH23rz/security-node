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

    VERIFIED evidence for a non-configured surface item is unexpected. Other
    observed states keep their imported value until later policy slices define
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

        if observed_state == "VERIFIED" and result_key not in expected_keys:
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


def load_scanner_results(scanner_results: Path | None) -> tuple[ScannerResult, ...]:
    """Load optional scanner results from a YAML evidence file.

    This does not run a scanner. It only ingests explicit observed evidence
    produced elsewhere, so the Controller never invents verification results.
    """

    if scanner_results is None:
        return ()

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

    for index, item in enumerate(loaded):
        if not isinstance(item, dict):
            raise ValueError(f"scanner result #{index + 1}: must be a mapping")

        missing = sorted(required_fields - set(item))
        if missing:
            raise ValueError(
                f"scanner result #{index + 1}: missing required field(s): {', '.join(missing)}"
            )

        port = item["port"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"scanner result #{index + 1}: port must be between 1 and 65535")

        protocol = str(item["protocol"]).strip().lower()
        if protocol not in ALLOWED_SCANNER_RESULT_PROTOCOLS:
            allowed = ", ".join(sorted(ALLOWED_SCANNER_RESULT_PROTOCOLS))
            raise ValueError(
                f"scanner result #{index + 1}: protocol must be one of: {allowed}"
            )

        observed_state = str(item["observed_state"]).strip().upper()
        if observed_state not in ALLOWED_SCANNER_RESULT_STATES:
            allowed = ", ".join(sorted(ALLOWED_SCANNER_RESULT_STATES))
            raise ValueError(
                f"scanner result #{index + 1}: observed_state must be one of: {allowed}"
            )

        results.append(
            ScannerResult(
                host_id=str(item["host_id"]),
                host_address=str(item["host_address"]),
                protocol=protocol,
                port=port,
                observed_state=observed_state,
                source=str(item["source"]),
                checked_at=str(item["checked_at"]),
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


def render_dashboard(output: Path, state: SecurityNodeState) -> None:
    """Render the current dashboard from normalized Controller state."""

    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    capabilities = ", ".join(state.controller_capabilities) if state.controller_capabilities else "none"
    expected_surface_rows = render_expected_surface_rows(state)
    observed_result_rows = render_observed_result_rows(state)
    security_confidence_class = _html.escape(confidence_class(state.security_confidence))
    security_confidence_text = _html.escape(state.security_confidence)
    security_confidence_badge = render_confidence_badge(state.security_confidence)

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Node</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    .page-header {{
      margin-bottom: 1.5rem;
    }}

    .page-title {{
      margin-bottom: 0.5rem;
    }}

    .page-meta {{
      margin: 0.35rem 0;
    }}

    .site-name,
    .verification-level,
    .validation-notice {{
      opacity: 0.95;
    }}

    .controller-state-list {{
      margin: 0;
    }}

    .controller-state-term {{
      font-weight: 700;
    }}

    .controller-state-value {{
      margin-left: 0;
      margin-bottom: 0.5rem;
    }}

    .configuration-summary-section {{
      margin-top: 1.5rem;
    }}

    .configuration-summary-heading {{
      margin-bottom: 0.5rem;
    }}

    .posture-summary {{
      padding-left: 1.25rem;
    }}

    .summary-metric {{
      margin: 0.25rem 0;
    }}

    .summary-metric-unexpected {{
      font-weight: 700;
    }}

    .expected-surface-section {{
      margin-top: 1.5rem;
    }}

    .expected-surface-heading {{
      margin-bottom: 0.5rem;
    }}

    .expected-surface-description {{
      margin: 0.35rem 0 0.75rem;
    }}

    .expected-surface-table {{
      border-collapse: collapse;
      width: 100%;
    }}

    .expected-surface-cell {{
      vertical-align: top;
    }}

    .observed-results-section {{
      margin-top: 1.5rem;
    }}

    .observed-results-heading {{
      margin-bottom: 0.5rem;
    }}

    .observed-results-description {{
      margin: 0.35rem 0 0.75rem;
    }}

    .observed-results-table {{
      border-collapse: collapse;
      width: 100%;
    }}

    .observed-result-cell {{
      vertical-align: top;
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
      opacity: 0.8;
    }}

    .status-verified,
    .status-accepted {{
      opacity: 1;
    }}

    .status-unexpected {{
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
      opacity: 0.8;
    }}

    .confidence-low {{
      font-weight: 800;
    }}

    .confidence-medium {{
      opacity: 1;
    }}
  </style>
</head>
<body>
  <main>
    <header class="page-header">
      <h1 class="page-title">Security Node</h1>
      <p class="page-meta site-name">Site: {_html.escape(state.site_name)}</p>
      <div class="page-meta page-security-confidence">
        <p class="security-confidence {security_confidence_class}" aria-label="Security Confidence: {security_confidence_text}"><span class="confidence-label">Security Confidence:</span> {security_confidence_badge}</p>
      </div>
      <p class="page-meta verification-level">Verification Level: {_html.escape(state.verification_level)}</p>
      <p class="page-meta validation-notice">Config schema validation passed before rendering.</p>
    </header>

    <section class="controller-state-section" aria-labelledby="controller-state">
      <h2 id="controller-state" class="controller-state-heading">Controller State</h2>
      <dl class="controller-state-list">
        <dt class="controller-state-term controller-state-controller-id-label">Controller ID</dt>
        <dd class="controller-state-value controller-state-controller-id">{_html.escape(state.controller_id)}</dd>
        <dt class="controller-state-term controller-state-display-name-label">Controller Display Name</dt>
        <dd class="controller-state-value controller-state-display-name">{_html.escape(state.controller_display_name)}</dd>
        <dt class="controller-state-term controller-state-network-label">Controller Network</dt>
        <dd class="controller-state-value controller-state-network">{_html.escape(state.controller_network)}</dd>
        <dt class="controller-state-term controller-state-capabilities-label">Controller Capabilities</dt>
        <dd class="controller-state-value controller-state-capabilities">{_html.escape(capabilities)}</dd>
      </dl>
    </section>

    <section class="configuration-summary-section" aria-labelledby="configuration-summary">
      <h2 id="configuration-summary" class="configuration-summary-heading">Configuration Summary</h2>
      <ul class="posture-summary">
        <li class="summary-metric summary-metric-networks">Networks: {state.network_count}</li>
        <li class="summary-metric summary-metric-hosts">Hosts: {state.host_count}</li>
        <li class="summary-metric summary-metric-probes">Probes: {state.probe_count}</li>
        <li class="summary-metric summary-metric-accepted-risks">Accepted Risks: {state.accepted_risk_count}</li>
        <li class="summary-metric summary-metric-external-exposure">External Exposure Expectations: {state.external_exposure_expected_count}</li>
        <li class="summary-metric summary-metric-expected-surface">Expected Verification Surface Items: {state.expected_surface_count}</li>
        <li class="summary-metric summary-metric-expected-not-verified">Expected Surface NOT VERIFIED: {state.expected_surface_not_verified_count}</li>
        <li class="summary-metric summary-metric-observed-results">Observed Scanner Results: {state.observed_result_count}</li>
        <li class="summary-metric summary-metric-unexpected">Observed Scanner Results UNEXPECTED: {state.observed_result_unexpected_count}</li>
      </ul>
    </section>

    <section class="expected-surface-section" aria-labelledby="expected-verification-surface">
      <h2 id="expected-verification-surface" class="expected-surface-heading">Expected Verification Surface</h2>
      <p class="expected-surface-description">Configured host ports that should be checked by future scanner logic.</p>
      <table class="expected-surface-table">
        <thead>
          <tr>
            <th>Host</th>
            <th>Address</th>
            <th>Network</th>
            <th>Protocol</th>
            <th>Port</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
{expected_surface_rows}
        </tbody>
      </table>
    </section>

    <section class="observed-results-section" aria-labelledby="observed-scanner-results">
      <h2 id="observed-scanner-results" class="observed-results-heading">Observed Scanner Results</h2>
      <p class="observed-results-description">Scanner result model is prepared, but live scanner logic is not implemented yet.</p>
      <table class="observed-results-table">
        <thead>
          <tr>
            <th>Host ID</th>
            <th>Address</th>
            <th>Protocol</th>
            <th>Port</th>
            <th>Observed State</th>
            <th>Source</th>
            <th>Checked At</th>
          </tr>
        </thead>
        <tbody>
{observed_result_rows}
        </tbody>
      </table>
    </section>

    <p>Scanner logic is not implemented yet.</p>
    <p>Generated: {now}</p>
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
        observed_results = load_scanner_results(scanner_results)
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
