# Screenshot reference

Captured October 13, 2026 from an isolated `0.6.45-dev` management build. The served HTML, JavaScript and other web-root assets matched this repository's source snapshot by SHA-256 comparison before capture.

The images show the actual interface with synthetic sensors and events. No production server was contacted, no response was issued and no trust policy was published. Sample user/process/PID fields demonstrate presentation, not OS attribution. The all-`A` hash in the draft whitelist is a documentation placeholder.

Desktop images use a 1,440 × 1,000 viewport; mobile images use 390 × 844. Full-page captures can be taller. Empty views intentionally show the first-use state.

## Navigation and monitoring

| Screen | Image |
| --- | --- |
| Sign in | [Desktop](screenshots/sign-in-desktop.png) |
| Overview | [Desktop](screenshots/overview-desktop.png) |
| Sensors | [Desktop](screenshots/sensors-desktop.png) · [Mobile](screenshots/sensors-mobile.png) |
| Event history | [Desktop](screenshots/events-desktop.png) · [Mobile](screenshots/events-mobile.png) |
| Canary tokens | [Desktop](screenshots/canaries-desktop.png) |

## Configuration and investigation

| Screen | Image |
| --- | --- |
| Group policies | [Desktop](screenshots/policies-desktop.png) |
| Trust rules, first use | [Desktop](screenshots/trust-rules-desktop.png) |
| Disabled whitelist draft | [Desktop](screenshots/whitelist-editor-desktop.png) |
| Notifications | [Desktop](screenshots/notifications-desktop.png) |
| Reports and schedules | [Desktop](screenshots/reports-desktop.png) |
| Operations | [Desktop](screenshots/operations-desktop.png) |
| Incidents | [Desktop](screenshots/incidents-desktop.png) |
| Responses | [Desktop](screenshots/responses-desktop.png) |
| Accounts | [Desktop](screenshots/accounts-desktop.png) |
| Account security | [Desktop](screenshots/account-security-desktop.png) |
| Windows decoy jobs | [Desktop](screenshots/decoy-jobs-desktop.png) |

## Capture and review

See [Development](DEVELOPMENT.md) for the reproducible capture command. [Capture metadata](screenshots/capture.json) records time, version, images and checks.

Screenshots are not evidence that every feature is deployed or accepted. The known Overview refresh problem is recorded in [Capabilities](CAPABILITIES.md); the image shows a successful initial load.
