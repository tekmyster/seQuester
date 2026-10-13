# Official Docker Hub library/debian 13-slim amd64 digest, queried 2026-09-13.
FROM debian@sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f
RUN apt-get update && apt-get install -y --no-install-recommends libaudit1 libstdc++6 libgcc-s1 zlib1g libssl3t64
ENV SEQUESTER_RULE_MASK_FIXTURE=1 DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
COPY mask-fixture/ /fixture/mask-fixture/
COPY fixture/ /fixture/fixture/
COPY status-fixture/ /fixture/status-fixture/
COPY mask.sh /fixture/mask.sh
RUN chmod 0755 /fixture/mask-fixture/AuditRuleMaskFixture /fixture/fixture/AuditRuleFixture /fixture/status-fixture/AuditStatusFixture
ENTRYPOINT ["/bin/bash", "/fixture/mask.sh"]
