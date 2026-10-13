# Build only on the approved isolated ops01 runner. Verify this local base image
# ID before use: sha256:fa624bbc2e6bc5dac23ab4132261cdacb6520b4f8ab0ab395d8bd02fd4f15431
FROM sequester-audit-relay:0.9.1-build1
RUN apt-get update && apt-get install -y --no-install-recommends libauparse0 util-linux jq
ENV SEQUESTER_TRANSPORT_FIXTURE=1 DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
COPY app/ /fixture/app/
COPY fixture.sh /fixture/fixture.sh
RUN chmod 0755 /fixture/app/RansomFree.LinuxAgent /out/RansomFree.AuditRelay /fixture/fixture.sh
ENTRYPOINT ["/bin/bash", "/fixture/fixture.sh"]
