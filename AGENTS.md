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
