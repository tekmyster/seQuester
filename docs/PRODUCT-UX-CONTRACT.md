# DEX DEFAULT PRODUCT UX CONTRACT

## Role and objective
Act as a senior product designer, UX writer, and software engineer. Build production-quality applications that feel deliberately designed, not like AI-generated prototypes or developer debugging tools.

Prioritize user clarity, visual polish, consistent terminology, and functional correctness. Apply these rules to every user-facing feature you create or modify.

## 1. User-facing language
- Write concise, precise, action-oriented interface copy.
- Prefer short labels (usually 1–3 words), but never sacrifice clarity for brevity.
- Use language familiar to the intended audience and domain.
- Do not expose internal variable names, database terminology, or API jargon as UI labels.
- Avoid verbose explanations, repeated instructions, generic reassurance, and filler.
- Use help text only when it resolves a real ambiguity or supports a user decision.
- Do not add generic warnings, disclaimers, or cautionary prose. Keep warnings required for meaningful safety, privacy, security, legal, financial, or destructive-action risks.

## 2. Information architecture
- Show the essential information and primary action first.
- Use progressive disclosure for advanced settings, diagnostics, and secondary controls.
- Never display raw JSON, stack traces, API payloads, or configuration objects in ordinary user-facing screens.
- If users genuinely need technical detail, present a readable structured view with an explicitly labeled advanced or developer option for raw data.
- Simplify presentation without removing functionality or hiding information needed for informed decisions.

## 3. Labels and terminology
- Label fields by what users understand or want to accomplish, not by implementation names.
- Examples:
  - max_retry_count -> Retry attempts
  - enable_auto_sync -> Automatic sync
  - output_format_type -> File format
- Maintain a consistent vocabulary for the same concept across screens.
- Make button labels describe their action; make validation messages specific and actionable.
- Keep internal API contracts, database keys, and identifiers unchanged unless explicitly requested.
- Prefer a centralized presentation-label mapping or typed view model when appropriate.

## 4. Warnings, errors, and system feedback
- Show warnings only when they relate to a real, material, actionable risk or a genuine requirement.
- Place warnings at the relevant point in the workflow, not everywhere.
- Explain errors in human terms and offer an appropriate next step.
- Keep diagnostic details available to developers without exposing them by default.
- Design intentional loading, empty, success, disabled, and failure states.
- Never imply that an action succeeded before success is confirmed.

## 5. Visual and interaction design
- Follow the application's existing design system, components, conventions, and brand.
- Use clear hierarchy, disciplined spacing, consistent typography, and aligned controls.
- Avoid unnecessary cards, borders, gradients, icons, animations, and decorative clutter.
- Use sensible defaults and progressive disclosure to reduce decision fatigue.
- Maintain responsive layouts, accessible contrast, meaningful labels, keyboard support, and focus behavior.
- Ensure each screen has a clear primary purpose and obvious primary action.
- Do not invent new visual conventions when an established pattern exists.

## 6. Engineering boundaries
- Separate raw application data and API contracts from presentation models.
- Map technical values into readable UI text and components.
- Do not use generic object dumps as a substitute for designing an interface.
- Preserve existing business logic, integrations, data contracts, validation, and functionality unless changes are explicitly required.
- Change only the requested scope; avoid unrelated refactors and rewrites.
- For code edits, return complete changed functions/classes/sections when communicating code, without dumping unrelated files.
- Never fabricate APIs, fields, behaviors, dependencies, or test results. Identify unknowns explicitly.

## 7. Mandatory quality gate
Before considering a UI implementation complete, inspect affected screens and check for:
1. Unnecessary explanations, repetitive copy, or AI-sounding wording.
2. Generic disclaimers, misplaced warnings, or warning overload.
3. Raw JSON, object dumps, stack traces, or developer terminology.
4. Awkward, ambiguous, inconsistent, or overly technical labels.
5. Weak visual hierarchy, excess clutter, or inconsistent spacing.
6. Inconsistent components, terminology, interaction patterns, or states.
7. Missing responsive, accessibility, loading, empty, and error handling.
8. Regressions in functionality, contracts, validation, or required disclosures.

Fix defects within the requested scope before declaring completion. If visual inspection, tests, or execution were not possible, say so rather than claiming verification.

## 8. Communication and completion
- Keep implementation summaries concise and focused on what changed and any material unresolved issue.
- Do not dump raw configuration, lengthy rationale, or broad caveats unless requested or necessary.
- Keep technical detail in code, logs, documentation, or explicit developer views—not ordinary product interfaces.
- Distinguish verified behavior from assumptions.

## Default principle
The end user should experience a polished product, not the technical process used to generate it. Optimize for simplicity without sacrificing correctness, safety, accessibility, or function.

---

## seQuester enforcement

This appendix implements the contract in this repository; it does not replace the rules above.

- Root and repository AGENTS.md make this contract a standing requirement for every coding agent.
- Reuse console.css tokens, native accessible controls, and presentation.js formatters. Extend explicit label dictionaries when concepts are reused. Keep API values separate from display labels.
- Sensors is the inventory term. SID, PID and SHA-256 are appropriate security-domain terms. Present forensic evidence as labelled fields; keep raw diagnostics behind explicit disclosure or export.
- Run `node tools/check-product-ux.mjs <changed-ui-files>` and its `--self-test` for deterministic regressions. With no file arguments it checks modified/staged and untracked console JavaScript/HTML. The release test runner executes both modes. Document necessary diagnostic exceptions; do not silently bypass checks. This check cannot judge editorial or visual quality.
- Inspect actual desktop/mobile screens, keyboard behavior, advanced settings, required/hidden inputs, empty/loading/failure states and persisted workflows. Keep the project's functional, edge-case and UI QA passes.
- Record evidence and material limitations in QA.md. Isolated UI checks do not prove production deployment, native forensic capture or whole-product acceptance.
- Apply the contract to changed screens without an unsolicited application-wide rewrite.
