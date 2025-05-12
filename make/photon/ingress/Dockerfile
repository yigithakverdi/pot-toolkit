FROM BASE_IMAGE

COPY --chown=dpdk:dpdk build/bin/dpdk-pot-ingress /usr/local/bin/
COPY --chown=dpdk:dpdk scripts/ingress/* /opt/dpdk-pot/scripts/

USER dpdk

ENTRYPOINT ["/usr/local/bin/dpdk-pot-ingress"]