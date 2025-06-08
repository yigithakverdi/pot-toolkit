FROM photon-dpdk-base:latest

# Copy the compiled DPDK application
COPY --chown=dpdk:dpdk build/bin/dpdk-pot-egress /usr/local/bin/
COPY --chown=dpdk:dpdk scripts/egress/* /opt/dpdk-pot/scripts/

# Copy component-specific configuration
COPY --chown=dpdk:dpdk config/egress.conf /etc/dpdk-pot/config/

# Set necessary capabilities
USER root
RUN setcap 'cap_net_admin+ep' /usr/local/bin/dpdk-pot-egress

# Switch to dpdk user
USER dpdk

# Configure DPDK EAL parameters
ENV DPDK_ARGS="--lcores=1 --socket-mem=512 --huge-dir /mnt/huge"

ENTRYPOINT ["/usr/local/bin/dpdk-pot-egress"]
CMD ["$DPDK_ARGS"]