<!--
// Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.
// seQuester — Proprietary Commercial License.
-->

# Editions and licensing

The governing terms are in [LICENSE](../LICENSE). This guide explains the edition choices; it does not replace those terms.

## Choose an edition

| Use | License requirement |
| --- | --- |
| Personal, homelab or education | Community is free, with no license key or endpoint cap. Enterprise-only features require an Enterprise license. |
| Small business with fewer than 50 enrolled Windows/Linux endpoints across all sites | Community is free unless Enterprise features are needed. |
| Business with exactly 50 or more endpoints | Commercial Enterprise license. |
| MSP/MSSP managing client endpoints | Commercial license at any endpoint count. |
| Qualified registered non-profit | Community is free; verified organizations qualify for free unlimited Enterprise with a non-expiring key. |
| Hosted SaaS or multi-tenant service offered to third parties | Commercial OEM agreement. |

An endpoint is a unique enrolled Windows or Linux agent under the license. The business threshold applies across all sites. Do not treat separate sites as separate allowances.

## Community scope

Community terms cover the management server, callback receiver, Windows/Linux sensors, native capture sources, canary templates, evidence and attribution, forensic bundles, ordinary syslog forwarding and local history. Community support is through GitHub Issues.

These rights do not establish that every feature is complete or qualified on every host. See [Capabilities](CAPABILITIES.md) for actual implementation and acceptance status.

## Enterprise scope

The license reserves active response/process controls, advanced whitelists and path leasing, Linux hash-based whitelisting, premium Wazuh/SIEM integration, central deployment tooling, signed packages, HA/migration support, SSO and paid support/SLA for Enterprise.

Ordinary syslog forwarding is in Community; premium Wazuh/SIEM integration is an Enterprise entitlement. A feature appearing in source does not establish a qualified Enterprise release.

For paid Enterprise or OEM terms, contact **licensing@tekmyster.com**. The written agreement determines paid terms. [LICENSE-COMMERCIAL](../LICENSE-COMMERCIAL) is an agreement-contact notice, not an executed commercial contract.

## Non-profit Enterprise

Email **nonprofits@tekmyster.com** with organization name, the 501(c)(3) determination letter or international equivalent, and estimated endpoint count. The policy provides qualified organizations a free Enterprise key with unlimited endpoints and no expiration.

Verification and key issuance are separate from this documentation update.

## Current implementation boundary

No Community/Enterprise license-key validator, endpoint-cap enforcement or commercial feature gate was found in the current source. These are licensing requirements, not implemented runtime controls. Existing authentication, policy/readiness checks and deployment safeguards operate independently.

Server bootstrap secrets and sensor enrollment credentials are still required. They are authentication credentials, not edition license keys.

Do not report edition enforcement, key issuance, HA, signed packages or other unfinished Enterprise capabilities as complete based on license text. The current Development-only server/receiver gate and recorded acceptance limitations still apply.

## Source and third-party terms

Internal modification and contribution are permitted by LICENSE. Copyright and license gates must be retained. Enterprise-only binary redistribution and third-party hosted service use have the restrictions stated there.

Native sources and dependencies keep their original licenses. The Community/Enterprise grant does not relicense those materials or resolve the existing MIT/Apache-2.0 core-policy audit findings in [Third-party notices](../THIRD-PARTY-NOTICES.md).
