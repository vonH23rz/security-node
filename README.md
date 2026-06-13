# Security Node

Security Node is a calm homelab security-confidence dashboard.

It verifies whether an environment still matches the intended safe design by comparing observed security posture against expected state.

Security Node is not a SOC, not a hacking toolkit, and not a noisy vulnerability dump.

## Current status

Controller skeleton, configuration validation, imported scanner-evidence validation, confidence calculation, and static dashboard rendering are in place.

The current Controller can:

- validate the configuration file before rendering;
- build an expected verification surface from configured hosts and ports;
- optionally ingest explicit scanner-result evidence from a YAML file;
- reject stale, future-dated, duplicate, malformed, or unsupported scanner-result evidence;
- classify non-matching observed evidence as `UNEXPECTED`;
- compute calm security confidence as `UNKNOWN`, `LOW`, or `MEDIUM`;
- render a static HTML dashboard with stable CSS hooks and the shared vonH23rz status palette.

Live scanner execution is not implemented yet. Security Node does not currently run Nmap, Lynis, Trivy, external exposure checks, or router-specific integrations by itself.

## Core idea

Sanity Node provides operational confidence.

Security Node provides security confidence.

Security Node should answer:

- what is expected;
- what is verified;
- what is unexpected;
- what is accepted;
- what is unknown;
- where to look next.

## Confidence model

Security Node currently uses three confidence states:

- `UNKNOWN` — the expected surface is not fully verified yet, or there is not enough fresh `VERIFIED` evidence to raise confidence;
- `LOW` — observed evidence conflicts with the configured expected surface, for example through `UNEXPECTED` exposure;
- `MEDIUM` — every expected surface item is verified by fresh imported evidence and there are no unexpected observations.

There is intentionally no `HIGH` confidence state yet.

`MEDIUM` is currently the ceiling because scanner evidence is imported from YAML. It is not collected by independent live scanner execution yet.

## Dashboard

The dashboard is static HTML generated from validated Controller state.

Current dashboard sections include:

- page header with site name, security confidence, verification level, and validation notice;
- Controller State;
- Configuration Summary;
- Expected Verification Surface;
- Observed Scanner Results;
- footer notice stating that scanner logic is not implemented yet.

The dashboard uses a centered, card-style layout with a system font stack, shared background, rounded white sections, subtle borders, padded tables, and stable CSS class hooks for future polish.

## Status palette

Security Node uses the shared vonH23rz status palette:

| Meaning | Color |
| --- | --- |
| `LOW` / `UNEXPECTED` | red `#ff4539` |
| `MEDIUM` | blue `#9cc9ff` |
| `UNKNOWN` / `NOT VERIFIED` | grey `#b3b6b6` |
| `VERIFIED` | green `#34c759` |
| `ACCEPTED` | indigo `#0a84ff` |
| page background | `#f3f5f7` |
| text | `#53585f` |

## Scanner evidence

Scanner evidence is optional and imported from YAML.

Security Node validates imported scanner evidence before rendering. Invalid evidence makes the Controller refuse to render a dashboard.

Current scanner-evidence rules include:

- evidence must be a YAML list;
- each result must include required fields;
- protocol must be `tcp` or `udp`;
- observed state must be `ACCEPTED`, `UNEXPECTED`, `UNKNOWN`, or `VERIFIED`;
- port must be between `1` and `65535`;
- `checked_at` must be an ISO-8601 timestamp with timezone offset;
- future timestamps are rejected beyond the configured tolerance;
- stale evidence is rejected according to the configured freshness window;
- duplicate result keys are rejected.

The scanner evidence freshness window is configurable with `controller.scanner_evidence_max_age_minutes`.

The allowed range is `30` to `1440` minutes in 30-minute steps. The example homelab default is `1440` minutes.

## Initial goals

- Docker-first Controller
- Linux-compatible codebase
- Configuration-driven expected state
- Nmap-based Network Exposure MVP
- Sanity Node-style static dashboard
- Probe-ready architecture from the beginning
- No private/public split

## Non-goals for the first MVP

- No working live probes yet
- No Lynis automation yet
- No Trivy automation yet
- No external exposure scanner yet
- No router-specific integration yet
- No `HIGH` confidence state yet

## Documentation approach

This repository intentionally keeps documentation simple and effective.

GitHub should contain the essentials:

- what Security Node is;
- how to install it;
- how to configure it;
- how to run it;
- what the current release supports.

Deeper documentation, architecture notes, design rationale, troubleshooting, operational examples, and background explanations belong in the Wiki.
