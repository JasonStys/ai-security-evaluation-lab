# Installed Windows 1.1.1 validation · 11 November 2026

By Jason Stys. These observations refer to the independently downloaded, published **1.1.1** application built from `ce8e0df93fd3efa581d5ae49805bf3f80c5608b1`. Historical 1.1.0 documents and release assets remain unchanged.

## Actual installed results

**Actual installed workflows: Passed.** Full original domain, review and export controls passed two normal native launches; all 5 saved bundles retained exact original bytes.

**Old-to-new profile: Passed.** The actual installed 1.1.0 app created a synthetic profile; installed 1.1.1 reopened it and retained all 5 exact bundles without reset.

**Source and distribution: Verified.** Exact-main workflows and processed CodeQL passed with zero open main alerts. Five downloaded assets and installed files matched their verified SHA-256 identities.

**PC and links: Verified.** Existing links were backed up and retargeted with settings retained. Normal profiles and Docker were unchanged; default-profile shortcut activation remains separately untested.

## User workflow and implementation

The [four-page illustrated guide](windows-application-guide-1.1.1.docx) contains two actual installed-app screenshots, a practical user journey, an immutable-source code excerpt and measured validation with operating limits. The [review manifest](windows-application-guide-1.1.1.json) binds the Word, screenshot, code-source and rendered-page hashes. All 40 final page contents across this batch were individually inspected; each Office package passed schema validation. Prepared data stays inside the actual application workflow.

## Installation, private data and limitations

Use the matching Windows EXE, checksum and notices from Releases; no system Python or terminal setup is needed.

Open the verified Desktop icon. Help describes supported inputs and workflow limits; close through the app's owner controls and back up its external data directory after a normal exit.

Authored or imported response replay only; no model, API or downstream tool is executed, and semantic answers are not graded. Model, context and approval labels are trusted operator assertions, not authenticated provider identity or a model-security certification.

Prepared inputs and acceptance used synthetic data only; normal profiles were not opened and Docker was unchanged. Local plaintext is trusted-OS-owner data, not protection against that OS user or administrator.

The actual installed 1.1.0 app created the synthetic profile used for the 1.1.1 upgrade test. Saved evidence retained exact bytes after the new app reopened it; no normal user profile was opened or reset. Desktop and Start-menu links were backed up and retargeted, retaining other settings. Target/arguments/read-back verification is distinct from default-profile shortcut activation, which was not independently exercised. Docker was unchanged. This documentation change requires its own full hosted checks; the runtime observations do not certify later source changes.
