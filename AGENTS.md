# Source ownership and dependency policy

- Source is private by default. Create new repositories as private; publishing source requires explicit human authorization. Existing explicit authorization applies only to the repository and scope authorized.
- Copyright owner: **Tekmyster Industries, LLC**. First-party source uses [LICENSE](LICENSE), with Community and Enterprise rights. Native sources retain their original licenses under Section 6. Preserve those terms without automatically approving core integration.
- Every new first-party file must include `Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.` and `seQuester — Proprietary Commercial License.` Use valid comment syntax. Formats without comments use a same-name `.license` sidecar containing the required notice; do not alter API/data schemas to insert comments.
- Preserve third-party ownership and upstream licenses. Do not stamp Tekmyster ownership over imported third-party material. New imports require retained notices, inventory and explicit owner review if the license is outside policy.
- Core library dependencies, including transitive and bundled native components, must be MIT or Apache-2.0. GPL/LGPL/AGPL, other licenses, custom terms and unknown licenses are not approved. Do not infer native approval from a wrapper package's MIT license.
- Track exact package versions and upstream terms in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Update notices whenever dependencies change.
- Run `python tools/check-license-policy.py --self-test` and `python tools/check-license-policy.py` before accepting dependency changes or declaring a compliant release. Use `--headers-only --base <ref>` to check new first-party files. Existing conflicts are failures, not grandfathered approvals.
- Resolve a conflict through an actual replacement, supported separation or explicit owner policy change. Do not strip upstream notices, invent a license, or change GPL declarations merely to pass checks. Preserve working deployments during licensing work.

# Permanent Product UX Contract

Every UI change must follow [docs/PRODUCT-UX-CONTRACT.md](docs/PRODUCT-UX-CONTRACT.md). Its editorial review, deterministic checks and actual desktop/mobile browser review are required completion gates. Preserve functionality, API contracts, validation, diagnostics, accessibility and necessary security information. This requirement applies to future work by every coding agent and does not authorize unrelated redesigns.

# Project QA requirement

## Later QA authorization (forwarded user instruction, 2026-09-14)

The deployment coordinating task forwarded the newer user instruction: “Work toward completing all backlog items that do not require my feedback. Do not pause or stop until all items are completed. Once completed, perform a three pass QA pass. After the QA pass, have the sequester chat update the documentation with all the updated features across all builds.” It explicitly confirms this supersedes the feature-phase test deferral for the current EA-032–EA-035, broker/service integration, branding and cross-platform release scope.

Continue isolated development checks while implementing; perform the distinct final product-wide three passes after implementation is complete. Do not make live deployments or alter accepted Linux 0.9.8. Preserve existing services, data, canaries and immutable artifacts. Missing native platforms/external systems are pending gates, not passes. Documentation receives the final immutable artifact/acceptance handoff only after completion. This does not add permission for production service/firewall changes or unrelated process termination. D: remains primary for test/build storage.

The older deferral below remains historical context and does not override this newer authorization for the stated scope.

## Development storage preference (user update, 2026-09-12)

Use D: as primary for configurable build/intermediate output, test databases, generated artifacts, logs and temporary files. Current root: `D:\Codex\RansomFree`; use .NET `--artifacts-path D:\Codex\RansomFree\artifacts` and process-local TEMP/TMP under that root. Keep existing source and installed tools in place unless a move is explicitly agreed. C: is a fallback for locations that cannot reasonably be redirected, including OS-managed cryptographic key storage; do not change system-wide settings or move/delete existing user data for this preference.

The user has now authorized testing all 19 implemented canary mechanisms on this development host. This supersedes the testing deferral for that scope only. Use isolated test storage/listeners, preserve live services/data, and record remaining native-client, external delivery and UI acceptance limitations. Signing and unrelated feature testing remain deferred.

## Current feature-build phase (user update, 2026-09-11)

The user has deferred code signing and full testing while features are built. During this phase, implement features and perform compilation/syntax checks as needed, but defer the three QA passes below. Record every deferred pass as pending in QA.md; compilation is not a functional or runtime pass. Keep builds unsigned and development-only. Do not deploy or change live systems. The three-pass checklist remains the acceptance backlog for the later testing phase.

The user requires a triple-check QA pass after every feature implementation.

1. Functional pass: test the new feature's normal path and persisted state.
2. Edge-case/regression pass: test invalid inputs, failure paths, preservation of user data, and relevant existing functionality. Fix failures and rerun affected passes.
3. UI/runtime pass: inspect changed screens, exercise the packaged app, and verify startup/tray behavior where applicable.

Record results and exact limitations in QA.md. A skipped or environment-dependent check is not a pass. Do not claim end-to-end remote callbacks or Wazuh delivery based on local generation or loopback tests alone. Do not deploy canaries into user folders, contact third-party token URLs, change live servers/firewalls, or terminate unrelated processes for QA.
