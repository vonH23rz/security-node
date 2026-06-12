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


def status_class(status: str) -> str:
    """Return the calm rendering class for a known status value."""

    return STATUS_CLASS_BY_NAME.get(status, "status-unknown")


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


def build_expected_surface(config_data: dict[str, Any]) -> tuple[ExpectedPort, ...]:
    """Build the expected host/port surface from validated host definitions.

    This is not scan output. It is the configured expectation that future
    scanner results will be compared against.
    """

    expected: list[ExpectedPort] = []

    for host in config_data.get("hosts", []):
        host_id = str(host["id"])
        host_display_name = str(host.get("display_name") or host_id)
        host_address = str(host["address"])
        network_id = str(host["network"])

        for port in host.get("expected_ports", []):
            expected.append(
                ExpectedPort(
                    host_id=host_id,
                    host_display_name=host_display_name,
                    host_address=host_address,
                    network_id=network_id,
                    protocol="tcp",
                    port=int(port),
                    verification_status="NOT VERIFIED",
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

        results.append(
            ScannerResult(
                host_id=str(item["host_id"]),
                host_address=str(item["host_address"]),
                protocol=str(item["protocol"]),
                port=port,
                observed_state=str(item["observed_state"]),
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
    expected_surface = build_expected_surface(config_data)

    controller_id = str(controller["id"])
    controller_display_name = str(controller.get("display_name") or controller_id)
    capabilities = tuple(str(capability) for capability in controller.get("capabilities", []))

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
        expected_surface_count=len(expected_surface),
        expected_surface_not_verified_count=sum(
            1 for item in expected_surface if item.verification_status == "NOT VERIFIED"
        ),
        observed_results=observed_results,
        observed_result_count=len(observed_results),
        verification_level="Controller only",
        security_confidence="UNKNOWN",
    )


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
        return "        <tr><td colspan=\"6\">No expected host ports configured.</td></tr>"

    rows = []
    for item in state.expected_surface:
        rows.append(
            "        <tr>"
            f"<td>{_html.escape(item.host_display_name)}</td>"
            f"<td>{_html.escape(item.host_address)}</td>"
            f"<td>{_html.escape(item.network_id)}</td>"
            f"<td>{_html.escape(item.protocol.upper())}</td>"
            f"<td>{item.port}</td>"
            f"<td>{render_status_badge(item.verification_status)}</td>"
            "</tr>"
        )

    return "\n".join(rows)


def render_observed_result_rows(state: SecurityNodeState) -> str:
    """Render observed scanner result rows.

    No rows are produced until scanner logic exists and provides evidence.
    """

    if not state.observed_results:
        return "        <tr><td colspan=\"7\">No scanner results collected yet.</td></tr>"

    rows = []
    for item in state.observed_results:
        rows.append(
            "        <tr>"
            f"<td>{_html.escape(item.host_id)}</td>"
            f"<td>{_html.escape(item.host_address)}</td>"
            f"<td>{_html.escape(item.protocol.upper())}</td>"
            f"<td>{item.port}</td>"
            f"<td>{render_status_badge(item.observed_state)}</td>"
            f"<td>{_html.escape(item.source)}</td>"
            f"<td>{_html.escape(item.checked_at)}</td>"
            "</tr>"
        )

    return "\n".join(rows)


def render_dashboard(output: Path, state: SecurityNodeState) -> None:
    """Render the current dashboard from normalized Controller state."""

    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    capabilities = ", ".join(state.controller_capabilities) if state.controller_capabilities else "none"
    expected_surface_rows = render_expected_surface_rows(state)
    observed_result_rows = render_observed_result_rows(state)

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Node</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
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
  </style>
</head>
<body>
  <main>
    <h1>Security Node</h1>
    <p>Site: {_html.escape(state.site_name)}</p>
    <p>Security Confidence: {_html.escape(state.security_confidence)}</p>
    <p>Verification Level: {_html.escape(state.verification_level)}</p>
    <p>Config schema validation passed before rendering.</p>

    <section aria-labelledby="controller-state">
      <h2 id="controller-state">Controller State</h2>
      <dl>
        <dt>Controller ID</dt>
        <dd>{_html.escape(state.controller_id)}</dd>
        <dt>Controller Display Name</dt>
        <dd>{_html.escape(state.controller_display_name)}</dd>
        <dt>Controller Network</dt>
        <dd>{_html.escape(state.controller_network)}</dd>
        <dt>Controller Capabilities</dt>
        <dd>{_html.escape(capabilities)}</dd>
      </dl>
    </section>

    <section aria-labelledby="configuration-summary">
      <h2 id="configuration-summary">Configuration Summary</h2>
      <ul>
        <li>Networks: {state.network_count}</li>
        <li>Hosts: {state.host_count}</li>
        <li>Probes: {state.probe_count}</li>
        <li>Accepted Risks: {state.accepted_risk_count}</li>
        <li>External Exposure Expectations: {state.external_exposure_expected_count}</li>
        <li>Expected Verification Surface Items: {state.expected_surface_count}</li>
        <li>Expected Surface NOT VERIFIED: {state.expected_surface_not_verified_count}</li>
        <li>Observed Scanner Results: {state.observed_result_count}</li>
      </ul>
    </section>

    <section aria-labelledby="expected-verification-surface">
      <h2 id="expected-verification-surface">Expected Verification Surface</h2>
      <p>Configured host ports that should be checked by future scanner logic.</p>
      <table>
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

    <section aria-labelledby="observed-scanner-results">
      <h2 id="observed-scanner-results">Observed Scanner Results</h2>
      <p>Scanner result model is prepared, but live scanner logic is not implemented yet.</p>
      <table>
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
        print("FAILED: refusing to render dashboard from invalid scanner resultss")
        return 1

    state = build_state_model(config_data, observed_results=observed_results)
    render_dashboard(output, state)
    print(f"Wrote dashboard from validated state model: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
