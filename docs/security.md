# Threat model and security limits

Author: Jason Stys.

Protected demo assets: tenant-a/doc-a, capability scope, approved draft arguments, current revision and reliable evidence. Malicious proposals may attempt cross-tenant access, approval forgery, marker disclosure, output injection or exhaustion.

Trusted: reviewed cases, process/dependencies, operator approval, harness clock, authored SQL and selected output directory ancestry. Untrusted: proposed responses and snapshot data. No real identity, provider or secret is used.

## Controls

| Boundary | Control | Failure |
| --- | --- | --- |
| Ingestion | 2 MiB file, 32 KiB record, 1,000 records, 128 opening-delimiter budget | Reject |
| JSON | Duplicate-key, UTF-8 and numeric-overflow validation | Reject |
| Response | Exact fields; 8,192 bytes answer/draft; one action; four citations | Block |
| Tool | Two narrow names; exact args; ASCII ID; integer not boolean revision | Block |
| Tenant/scope | Trusted context, doc-a allowlist and citation read scope | Block or unverified-citation review |
| Mutation | Exact MAC, expiry, single-use nonce, revision and atomic locks | Review or block |
| Known marker | Literal, Base64, hex, full percent encoding; NFKC/casefold | Block |
| Output | Escaped script-free HTML, restrictive meta CSP, no remote assets | Inert text |
| Evidence | Exclusive outputs, POSIX modes, SQL parameters/constraints | No overwrite |

There is no keyword-based injection classifier. Mentioning “ignore instructions” is not automatically rejected. Delimiters or labels alone do not establish authority.

## Limits

- Marker checks are not general DLP. Partial/chunked leakage, arbitrary encodings, steganography, paraphrase and multimodal content are untested.
- Citations validate allowed IDs only, not factual grounding. Refusal text with a citation is structurally accepted but never counted as completed.
- No inference occurs. Fixed proposal replay cannot establish real-model prompt attack success rates.
- Baseline “unsafe allow” means a deliberately permissive policy decision, not observed theft or actual tool execution.
- A compromised process can read approval keys. Trusted constructors are not authenticated APIs. Real auth, durable state and distributed approvals are absent.
- SQL triggers prevent accidental updates, not database-owner tampering. SHA256 provenance is neither authentication nor a signed audit trail.
- Windows inherits parent ACLs. POSIX modes are not encryption. Private snapshots/reports belong in appropriate local directories, never the public repo.
- Hashes can be linkable to guessed contents. Private data requires an independent privacy review.
- Meta CSP cannot provide HTTP-only framing protections; this is not a public web service.
- Bounds limit workload, not every resource-consumption attack. The delimiter preflight conservatively rejects even legitimate strings containing too many braces.

Use dummy secrets and owned/authorized environments. Provider calls, cost, dataset consent and retention must be approved separately. Do not disclose real secrets to a model to test leakage.

Report issues through [Jason Stys](https://github.com/JasonStys) without posting private inputs, keys, approvals or sensitive reports publicly. Passing CI is not a guarantee of security.
