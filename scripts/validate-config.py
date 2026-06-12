#!/usr/bin/env python3
"""Validate a Security Node YAML configuration.

This validator intentionally checks the first public configuration contract only.
It does not run scans and does not require private environment data.
"""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception as exc:  # pragma: no cover - dependency failure path
    raise SystemExit(f"ERROR: PyYAML is required: {exc}") from exc


KNOWN_CAPABILITIES = {
    "reachability",
    "nmap",
    "lynis",
    "trivy",
    "host_info",
    "manual",
}

EXPECTED_EXTERNAL_STATES = {
    "reachable",
    "blocked",
    "unknown",
    "not_configured",
}

RISK_STATUSES = {
    "accepted",
}


class ValidationReport:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")

    def warning(self, path: str, message: str) -> None:
        self.warnings.append(f"{path}: {message}")

    @property
    def ok(self) -> bool:
        return not self.errors


def is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def is_list(value: Any) -> bool:
    return isinstance(value, list)


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_id(value: Any, path: str, report: ValidationReport) -> str | None:
    if not is_non_empty_string(value):
        report.error(path, "must be a non-empty string")
        return None
    return value.strip()


def validate_ports(value: Any, path: str, report: ValidationReport) -> None:
    if not is_list(value):
        report.error(path, "must be a list of TCP/UDP port numbers")
        return

    seen: set[int] = set()
    for index, port in enumerate(value):
        item_path = f"{path}[{index}]"
        if isinstance(port, bool) or not isinstance(port, int):
            report.error(item_path, "must be an integer")
            continue
        if port < 1 or port > 65535:
            report.error(item_path, "must be between 1 and 65535")
            continue
        if port in seen:
            report.warning(item_path, f"duplicate port {port}")
        seen.add(port)


def validate_capabilities(value: Any, path: str, report: ValidationReport) -> None:
    if not is_list(value):
        report.error(path, "must be a list")
        return

    seen: set[str] = set()
    for index, capability in enumerate(value):
        item_path = f"{path}[{index}]"
        if not is_non_empty_string(capability):
            report.error(item_path, "must be a non-empty string")
            continue
        capability = capability.strip()
        if capability not in KNOWN_CAPABILITIES:
            report.warning(item_path, f"unknown capability '{capability}'")
        if capability in seen:
            report.warning(item_path, f"duplicate capability '{capability}'")
        seen.add(capability)


def validate_top_level(config: Any, report: ValidationReport) -> dict[str, Any]:
    if not is_mapping(config):
        report.error("$", "configuration root must be a mapping/object")
        return {}

    required = [
        "site",
        "controller",
        "networks",
        "hosts",
        "probes",
        "accepted_risks",
        "external_exposure",
    ]

    for key in required:
        if key not in config:
            report.error("$", f"missing required top-level key '{key}'")

    return config


def validate_site(config: dict[str, Any], report: ValidationReport) -> None:
    site = config.get("site")
    if not is_mapping(site):
        report.error("site", "must be a mapping/object")
        return

    if not is_non_empty_string(site.get("name")):
        report.error("site.name", "must be a non-empty string")


def validate_networks(config: dict[str, Any], report: ValidationReport) -> dict[str, ipaddress._BaseNetwork]:
    networks = config.get("networks")
    result: dict[str, ipaddress._BaseNetwork] = {}

    if not is_list(networks):
        report.error("networks", "must be a list")
        return result

    if not networks:
        report.error("networks", "must contain at least one network")

    seen_ids: set[str] = set()

    for index, network in enumerate(networks):
        path = f"networks[{index}]"
        if not is_mapping(network):
            report.error(path, "must be a mapping/object")
            continue

        network_id = validate_id(network.get("id"), f"{path}.id", report)
        if network_id:
            if network_id in seen_ids:
                report.error(f"{path}.id", f"duplicate network id '{network_id}'")
            seen_ids.add(network_id)

        subnet_value = network.get("subnet")
        if not is_non_empty_string(subnet_value):
            report.error(f"{path}.subnet", "must be a non-empty CIDR string")
            continue

        try:
            parsed = ipaddress.ip_network(subnet_value.strip(), strict=True)
        except ValueError as exc:
            report.error(f"{path}.subnet", f"invalid CIDR network: {exc}")
            continue

        if network_id:
            result[network_id] = parsed

        if "display_name" in network and not is_non_empty_string(network.get("display_name")):
            report.error(f"{path}.display_name", "must be a non-empty string when present")

        if "role" in network and not is_non_empty_string(network.get("role")):
            report.error(f"{path}.role", "must be a non-empty string when present")

    return result


def validate_controller(
    config: dict[str, Any],
    networks_by_id: dict[str, ipaddress._BaseNetwork],
    report: ValidationReport,
) -> None:
    controller = config.get("controller")
    if not is_mapping(controller):
        report.error("controller", "must be a mapping/object")
        return

    validate_id(controller.get("id"), "controller.id", report)

    if "display_name" in controller and not is_non_empty_string(controller.get("display_name")):
        report.error("controller.display_name", "must be a non-empty string when present")

    network_id = controller.get("network")
    if not is_non_empty_string(network_id):
        report.error("controller.network", "must be a non-empty string")
    elif network_id not in networks_by_id:
        report.error("controller.network", f"references unknown network '{network_id}'")

    validate_capabilities(controller.get("capabilities"), "controller.capabilities", report)


def validate_hosts(
    config: dict[str, Any],
    networks_by_id: dict[str, ipaddress._BaseNetwork],
    report: ValidationReport,
) -> None:
    hosts = config.get("hosts")
    if not is_list(hosts):
        report.error("hosts", "must be a list")
        return

    seen_ids: set[str] = set()
    seen_addresses: set[str] = set()

    for index, host in enumerate(hosts):
        path = f"hosts[{index}]"
        if not is_mapping(host):
            report.error(path, "must be a mapping/object")
            continue

        host_id = validate_id(host.get("id"), f"{path}.id", report)
        if host_id:
            if host_id in seen_ids:
                report.error(f"{path}.id", f"duplicate host id '{host_id}'")
            seen_ids.add(host_id)

        if "display_name" in host and not is_non_empty_string(host.get("display_name")):
            report.error(f"{path}.display_name", "must be a non-empty string when present")

        address_text = host.get("address")
        address = None
        if not is_non_empty_string(address_text):
            report.error(f"{path}.address", "must be a non-empty IP address string")
        else:
            try:
                address = ipaddress.ip_address(address_text.strip())
            except ValueError as exc:
                report.error(f"{path}.address", f"invalid IP address: {exc}")

        network_id = host.get("network")
        network = None
        if not is_non_empty_string(network_id):
            report.error(f"{path}.network", "must be a non-empty string")
        elif network_id not in networks_by_id:
            report.error(f"{path}.network", f"references unknown network '{network_id}'")
        else:
            network = networks_by_id[network_id]

        if address is not None:
            address_key = str(address)
            if address_key in seen_addresses:
                report.warning(f"{path}.address", f"duplicate host address '{address_key}'")
            seen_addresses.add(address_key)

            if network is not None and address not in network:
                report.error(f"{path}.address", f"is not inside referenced network '{network_id}'")

        if "expected_ports" in host:
            validate_ports(host.get("expected_ports"), f"{path}.expected_ports", report)


def validate_probes(
    config: dict[str, Any],
    networks_by_id: dict[str, ipaddress._BaseNetwork],
    report: ValidationReport,
) -> None:
    probes = config.get("probes")
    if not is_list(probes):
        report.error("probes", "must be a list")
        return

    seen_ids: set[str] = set()

    for index, probe in enumerate(probes):
        path = f"probes[{index}]"
        if not is_mapping(probe):
            report.error(path, "must be a mapping/object")
            continue

        probe_id = validate_id(probe.get("id"), f"{path}.id", report)
        if probe_id:
            if probe_id in seen_ids:
                report.error(f"{path}.id", f"duplicate probe id '{probe_id}'")
            seen_ids.add(probe_id)

        if "display_name" in probe and not is_non_empty_string(probe.get("display_name")):
            report.error(f"{path}.display_name", "must be a non-empty string when present")

        network_id = probe.get("network")
        network = None
        if not is_non_empty_string(network_id):
            report.error(f"{path}.network", "must be a non-empty string")
        elif network_id not in networks_by_id:
            report.error(f"{path}.network", f"references unknown network '{network_id}'")
        else:
            network = networks_by_id[network_id]

        if "address" in probe:
            address_text = probe.get("address")
            try:
                address = ipaddress.ip_address(str(address_text).strip())
            except ValueError as exc:
                report.error(f"{path}.address", f"invalid IP address: {exc}")
            else:
                if network is not None and address not in network:
                    report.error(f"{path}.address", f"is not inside referenced network '{network_id}'")

        if "capabilities" in probe:
            validate_capabilities(probe.get("capabilities"), f"{path}.capabilities", report)


def validate_accepted_risks(config: dict[str, Any], report: ValidationReport) -> None:
    risks = config.get("accepted_risks")
    if not is_list(risks):
        report.error("accepted_risks", "must be a list")
        return

    seen_ids: set[str] = set()

    for index, risk in enumerate(risks):
        path = f"accepted_risks[{index}]"
        if not is_mapping(risk):
            report.error(path, "must be a mapping/object")
            continue

        risk_id = validate_id(risk.get("id"), f"{path}.id", report)
        if risk_id:
            if risk_id in seen_ids:
                report.error(f"{path}.id", f"duplicate accepted risk id '{risk_id}'")
            seen_ids.add(risk_id)

        status = risk.get("status")
        if not is_non_empty_string(status):
            report.error(f"{path}.status", "must be a non-empty string")
        elif status.strip() not in RISK_STATUSES:
            report.warning(f"{path}.status", f"unknown accepted risk status '{status}'")

        if "reason" in risk and not is_non_empty_string(risk.get("reason")):
            report.error(f"{path}.reason", "must be a non-empty string when present")


def validate_external_exposure(config: dict[str, Any], report: ValidationReport) -> None:
    external = config.get("external_exposure")
    if not is_mapping(external):
        report.error("external_exposure", "must be a mapping/object")
        return

    expected = external.get("expected")
    if not is_list(expected):
        report.error("external_exposure.expected", "must be a list")
        return

    seen_ids: set[str] = set()

    for index, item in enumerate(expected):
        path = f"external_exposure.expected[{index}]"
        if not is_mapping(item):
            report.error(path, "must be a mapping/object")
            continue

        item_id = validate_id(item.get("id"), f"{path}.id", report)
        if item_id:
            if item_id in seen_ids:
                report.error(f"{path}.id", f"duplicate external exposure id '{item_id}'")
            seen_ids.add(item_id)

        if "hostname" in item and not is_non_empty_string(item.get("hostname")):
            report.error(f"{path}.hostname", "must be a non-empty string when present")

        if "ports" in item:
            validate_ports(item.get("ports"), f"{path}.ports", report)

        if "expected" in item:
            expected_state = item.get("expected")
            if not is_non_empty_string(expected_state):
                report.error(f"{path}.expected", "must be a non-empty string when present")
            elif expected_state.strip() not in EXPECTED_EXTERNAL_STATES:
                report.warning(f"{path}.expected", f"unknown external expected state '{expected_state}'")

        if "exposure_type" in item and not is_non_empty_string(item.get("exposure_type")):
            report.error(f"{path}.exposure_type", "must be a non-empty string when present")


def load_yaml(path: Path, report: ValidationReport) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except FileNotFoundError:
        report.error("config", f"file not found: {path}")
    except yaml.YAMLError as exc:
        report.error("config", f"invalid YAML: {exc}")
    except OSError as exc:
        report.error("config", f"could not read file: {exc}")
    return None


def validate_config(path: Path) -> ValidationReport:
    report = ValidationReport()
    loaded = load_yaml(path, report)
    if report.errors:
        return report

    config = validate_top_level(loaded, report)
    if not config:
        return report

    validate_site(config, report)
    networks_by_id = validate_networks(config, report)
    validate_controller(config, networks_by_id, report)
    validate_hosts(config, networks_by_id, report)
    validate_probes(config, networks_by_id, report)
    validate_accepted_risks(config, report)
    validate_external_exposure(config, report)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Security Node config")
    parser.add_argument("config", nargs="?", default="examples/config.example.yaml")
    args = parser.parse_args()

    config_path = Path(args.config)
    report = validate_config(config_path)

    print("Security Node config validation")
    print(f"config={config_path}")

    for warning in report.warnings:
        print(f"WARNING: {warning}")

    for error in report.errors:
        print(f"ERROR: {error}")

    print(f"summary: {len(report.errors)} error(s), {len(report.warnings)} warning(s)")

    if report.ok:
        print("OK: config schema is valid")
        return 0

    print("FAILED: config schema is invalid")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
