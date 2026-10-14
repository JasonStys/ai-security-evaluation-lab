# Coding and contribution rules

Author: Jason Stys.

Shallow structure: aisec runtime, sql schema, data public fixtures, tests, scripts, docs and two workflows. Use each language for its role; avoid redundant implementations.

Every Python file has a purpose header; every class/function has a description. Meaningful names, immutable context and narrow contracts provide self-documenting structure. Important trust/encoding sections are explained. Generated headers give exact physical lines for Python AST definitions, parameters, assignments and attribute stores. SQL/YAML indexes are lexical declarations, not full semantic analysis. Noncommentable JSON/locks have complete README descriptions.

```console
python -m ruff check . --fix
python -m ruff format .
python scripts/code_map.py
```

Stage only reviewed files, regenerate the file guide, then run full tests/types/maps/privacy/benchmark. Do not weaken coverage or change oracles to mask defects. Empty runtime graph; development/scanner/action versions are locked and audited against official releases.

Never commit external response data, generated databases, real accounts, keys, tokens, diagnostics or billing/archive evidence. out/ is ignored. The published canary is clearly fake, not a credential.

Minimum CI permissions, no pull_request_target, no artifacts/caches including CodeQL's implicit caches. Logs remain on GitHub and contain only synthetic inputs/safe metadata.

Extend tests/contracts/docs together. Document trust boundaries before adding providers or real side effects. This lab is source tooling with offline reports, not a production service, host or installer.
