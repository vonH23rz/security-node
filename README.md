# Security Node

Security Node is a calm homelab security-confidence dashboard.

It verifies whether an environment still matches the intended safe design by comparing observed security posture against expected state.

Security Node is not a SOC, not a hacking toolkit, and not a noisy vulnerability dump.

## Current status

Early architecture and Controller MVP planning.

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
