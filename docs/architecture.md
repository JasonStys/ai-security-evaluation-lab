# Architecture and technology decisions

Author: Jason Stys. Decisions accepted for this offline lab, 2026-10-14.

## Boundary flow

Reviewed context + untrusted proposal → strict contracts → caller-bound broker → narrow dummy operation → metadata grader → JSON / inert HTML / SQL.

The harness owns context and approval fixtures. A response cannot supply authority fields. `Case.message` and origin are scenario data: **no message is sent to a model**. Replay measures downstream enforcement against representative proposals, not whether a prompt causes a real model to produce one.

## ADR-001: Python evaluation and authorization

The standard library supplies typed dataclasses, strict JSON hooks, HMAC, locks, SQLite and reproducible reporting. Work is bounded parsing/metadata checks, not a native compute kernel. Empty runtime dependencies avoid an unnecessary compiled deployment chain. Ruff, strict mypy and Hypothesis guard maintainability and actual boundary behavior.

Alternative: live provider/framework integration. That would add credentials, data transmission, stochastic results and costs. It is separate future work, not an implied implemented feature.

## ADR-002: SQL evidence and HTML reading

SQLite supplies schemas, primary/foreign keys, CHECK constraints, transactions and an objective index. Values are bound parameters; only authored schema SQL is executed. Python's SQLite must support STRICT tables (3.37+) and JSON functions.

HTML is a portable script-free report, not a hosted application. Native headings, captions, scoped headers, escaped text and plain links need no JavaScript, login, tracking or remote assets. Adding TypeScript for static evidence would create unnecessary complexity.

## ADR-003: approval integrity outside the model

Immutable `Context`; ephemeral random key and bounded spent-nonce ledger in `Authority`. Broker checks current revision under its state lock, then verifies/spends exact approval before updating state. Lock order: broker → authority; authority never acquires a broker lock.

The trusted fixture operator approves the **original reviewed action**, not a changed imported proposal. Text/session/expiry/replay/capability/policy-revision changes and competing concurrent writes are tested. Model claims of approval grant nothing.

Consequences: single-process dummy state, invalid approvals after restart, fail-closed full replay ledger. Production needs authenticated operators, server-owned monotonic time, key lifecycle, durable transactional nonces, real tenant inventories and downstream enforcement. Public in-process Python APIs are not a sandbox against malicious host code.

## ADR-004: data-only adapters

No shell, URL fetch, arbitrary SQL or actual filesystem-mutating agent tools exist. Imported adapters are JSONL, not code. A model label is unverified provenance. Separate CI scanner installation is network-capable, restricted to official sources and pinned digests, and never accessible through the broker.
