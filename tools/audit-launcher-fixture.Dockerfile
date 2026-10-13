# Require local base ID sha256:fa624bbc2e6bc5dac23ab4132261cdacb6520b4f8ab0ab395d8bd02fd4f15431; --pull=false.
FROM sequester-audit-relay:0.9.1-build1
RUN apt-get update && apt-get install -y --no-install-recommends libauparse0 util-linux jq
ENV SEQUESTER_LAUNCHER_FIXTURE=1 DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ENV SEQUESTER_RULE_MASK_FIXTURE=1
COPY app/ /fixture/app/
COPY status-fixture/ /fixture/status-fixture/
COPY health-fixture/ /fixture/health-fixture/
COPY summary-fixture/ /fixture/summary-fixture/
COPY mask-fixture/ /fixture/mask-fixture/
COPY fixture/ /fixture/fixture/
COPY mask.sh /fixture/mask.sh
RUN chmod 0755 /fixture/mask-fixture/AuditRuleMaskFixture /fixture/fixture/AuditRuleFixture
COPY harness/ /fixture/harness/
RUN dotnet publish /fixture/harness/AuditLauncherFixture.csproj -c Release -r linux-x64 --self-contained true --artifacts-path /fixture/build -o /fixture/native-harness
COPY launch-relay.sh /opt/ransomfree-client/releases/ransomfree-client-0.9.10-dev.20260918T000000Z-55f982667923-linux-x64/audit/launch-relay.sh
COPY sequester.conf.example /fixture/sequester.conf
COPY fixture.sh /fixture/fixture.sh
RUN release=ransomfree-client-0.9.10-dev.20260918T000000Z-55f982667923-linux-x64 && mkdir -p "/opt/ransomfree-client/releases/$release/audit-relay" && cp /out/RansomFree.AuditRelay "/opt/ransomfree-client/releases/$release/audit-relay/" && printf '%s\n%s\n%s\n' "$release" linux-x64 "$(sha256sum "/opt/ransomfree-client/releases/$release/audit-relay/RansomFree.AuditRelay" | awk '{print $1}')" > "/opt/ransomfree-client/releases/$release/audit-relay/LAUNCHER_IDENTITY" && ln -s "releases/$release" /opt/ransomfree-client/current && chmod 0755 /fixture/app/RansomFree.LinuxAgent /fixture/status-fixture/AuditStatusFixture /fixture/health-fixture/AuditHealthFixture /fixture/summary-fixture/EndpointHealthSummaryFixture /opt/ransomfree-client/current/audit/launch-relay.sh /opt/ransomfree-client/current/audit-relay/RansomFree.AuditRelay
ENTRYPOINT ["/bin/bash", "/fixture/fixture.sh"]
