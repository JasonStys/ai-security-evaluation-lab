# AI Security Evaluation Lab handbook

By Jason Stys.

Replay paired reviewed cases against current broker policy and separate unsafe allowance, benign availability, completion and oracle coverage.

Replay paired reviewed cases against current broker policy and separate unsafe allowance, benign availability, completion and oracle coverage.

Avoids conflating unavailable or unreviewed model behavior with a successful safety result.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [usage](usage.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)
- [validation](validation.md)

## Historical results and reproduction

The reviewed source is [`8eaed87a77b787e95a54451c1529a9a184914d6e`](https://github.com/JasonStys/ai-security-evaluation-lab/tree/8eaed87a77b787e95a54451c1529a9a184914d6e). The observed functional workflow baseline is `8eaed87a77b787e95a54451c1529a9a184914d6e`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/paired-review-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/ai-security-evaluation-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Evaluation replays authored/imported snapshots; it does not run an inference provider or real downstream tool actions.
- Model labels are supplied assertions rather than authenticated model identities; there is no aggregate model ranking.
- Accepted-text semantics can remain ungraded, and a finite reviewed corpus does not prove universal model security.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
