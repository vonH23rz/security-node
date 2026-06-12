# Security Node

Security Node is a calm homelab security-confidence dashboard.

It verifies whether an environment still matches the intended safe design by comparing observed security posture against expected state.

Security Node is not a SOC, not a hacking toolkit, and not a noisy vulnerability dump.

## Current status

Controller skeleton and static dashboard MVP are in place.

The current Controller can:

- validate the configuration file before rendering;
- build an expected verification surface from configured hosts and ports;
- optionally ingest explicit scanner-result evidence from a YAML file;
- classify non-matching verified evidence as `UNEXPECTED`;
- compute calm security confidence as `UNKNOWN`, `LOW`, or `MEDIUM`;
- render a static HTML dashboard with stable CSS hooks for presentation work.

Live scanner execution is not implemented yet. Security Node does not currently run Nmap, Lynis, Trivy, external exposure checks, or router-specific integrations by itself.

## Core idea

Sanity Node provides operational confidence.

Security Node provides security confidence.

## Initial goals

- Docker-first Controller
- Linux-compatible codebase
- Configuration-driven expected state
- Nmap-based Network Exposure MVP
- Sanity Node-style static dashboard
- Probe-ready architecture from the beginning
- No private/public split

## Non-goals for the first MVP

- No working probes yet
- No Lynis automation yet
- No Trivy automation yet
- No external exposure scanner yet
- No router-specific integration yet

## Project philosophy

Security Node should tell the user:

- what is verified;
- what is exposed;
- what is unexpected;
- what is accepted;
- what is unknown;
- where to look next.

## Documentation approach

This repository intentionally keeps documentation simple and effective.

GitHub should contain the essentials:

- what Security Node is;
- how to install it;
- how to configure it;
- how to run it;
- what the current release supports.

Deeper documentation, architecture notes, design rationale, troubleshooting, operational examples, and background explanations belong in the Wiki.
