# Security Policy — Operator Console

## Scope & Operational Context

`operator-console` is an **experimental detection engineering control plane and research workbench**. It provides a web-based IDE, multi-backend transpiler, pull request review queue, and purple-team validation trigger interface for the [`detection-platform`](https://github.com/Ctum0/detection-platform) ecosystem.

This application is designed for **internal security operations teams, research environments, and controlled lab networks**.

## Operational Security Boundaries

### 1. Authentication & Perimeter
- **Demo Mode**: The live interactive sandbox (`?demo=1`) uses browser session storage (`sessionStorage`) to isolate simulated data. No server-side changes or GitHub mutations occur in demo mode.
- **Console Token Gate**: The API endpoints are protected by a shared bearer token (`CONSOLE_TOKEN`).
- **Production Hardening**: If deploying in an enterprise SOC:
  - Do not expose the console directly to the public internet without perimeter authentication.
  - Front the console with an Identity-Aware Proxy (Cloudflare Zero Trust, Google IAP, or Tailscale Funnel with SSO/MFA).
  - Transition to SAML 2.0 / OIDC with fine-grained Role-Based Access Control (RBAC).

### 2. Privilege Separation & GitHub Tokens
- The `GITHUB_TOKEN` fine-grained PAT requires:
  - `Pull requests: Read and write` (to manage PR review lifecycle).
  - `Contents: Read and write` (to submit detection rules and branches).
  - `Actions: Read and write` (to query CI status and dispatch validation workflows).
- **Mandate**: Keep this token strictly scoped to your dedicated detection repository. Never grant organization-wide administrative rights.

### 3. Attack Simulation Safety
- The simulation trigger interface dispatches adversary emulation into the detection repository's CI/CD runners.
- **Mandate**: Ensure self-hosted or cloud runners target dedicated, isolated sandbox VMs. Never execute automated attack triggers on production endpoints.

### 4. Transpiler Engine & Regex Complexity (ReDoS)
- The Sigma transpiler (`app/converter.py`) performs deterministic Abstract Syntax Tree (AST) transformations without invoking system shells or dangerous deserialization (`eval`/`pickle`).
- However, complex user-supplied regular expressions in custom Sigma rules can introduce catastrophic backtracking (ReDoS) if deployed to high-velocity ingestion streams. Validate rule regex patterns prior to production deployment.

## Reporting a Vulnerability

We appreciate responsible disclosure from the security research community.

If you discover a security vulnerability or sensitive information exposure:

1. **Do NOT open a public GitHub issue.**
2. Send a private report to **sithumsryt@gmail.com**, or submit a confidential advisory via **GitHub Private Vulnerability Reporting**.
3. Please provide:
   - A summary of the vulnerability and its potential blast radius.
   - Minimal reproduction steps or Proof of Concept (PoC).
   - The affected API endpoint, component, or file.

### Response Timeline

- **Acknowledgment**: Within 48 hours.
- **Assessment**: Severity and impact evaluated in our lab testbed.
- **Remediation**: Coordinated fix committed to `main` with attribution.
