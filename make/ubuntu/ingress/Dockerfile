# Dockerfile for the generic "dpdk-pot-app"
# This single image can be run as ingress, transit, or egress
# by passing different command-line arguments.

# Assumes 'photon-dpdk-base:latest' contains:
# - Photon OS
# - DPDK runtime libraries (e.g., libnuma, libpcap)
# - 'dpdk' user and group
# - NO build tools or hugepage setup commands
FROM photon-dpdk-base:latest

ARG APP_USER=dpdk
ARG APP_GROUP=dpdk

# Create application-specific directories and set ownership
# These directories will be used for scripts, logs, and potentially mounted configurations.
RUN mkdir -p /opt/dpdk-pot/scripts \
             /etc/dpdk-pot/mounted_config \
             /var/log/dpdk-pot && \
    chown -R ${APP_USER}:${APP_GROUP} /opt/dpdk-pot \
                                      /etc/dpdk-pot \
                                      /var/log/dpdk-pot

# Copy the single compiled DPDK application binary
# This binary is expected to handle different roles based on CLI arguments.
# Ensure 'build/bin/dpdk-pot' exists in your Docker build context.
COPY --chown=${APP_USER}:${APP_GROUP} build/bin/dpdk-pot /usr/local/bin/dpdk-pot

# Copy common scripts (if any)
# These scripts might be helpers used by all node types.
# Ensure 'scripts/common/' exists in your Docker build context if you have common scripts.
COPY --chown=${APP_USER}:${APP_GROUP} scripts/common/* /opt/dpdk-pot/scripts/

# Copy role-specific scripts (optional, if needed and not handled by main binary logic)
# Example: if you had specific startup wrappers or health checks per role.
# This example assumes most logic is in the main binary.
# COPY --chown=${APP_USER}:${APP_GROUP} scripts/ingress/* /opt/dpdk-pot/scripts/ingress/
# COPY --chown=${APP_USER}:${APP_GROUP} scripts/transit/* /opt/dpdk-pot/scripts/transit/
# COPY --chown=${APP_USER}:${APP_GROUP} scripts/egress/* /opt/dpdk-pot/scripts/egress/

# Copy default/fallback configuration files (optional)
# Your 'prepare' script will likely mount a specific, generated config file
# that overrides these defaults.
# Example:
# COPY --chown=${APP_USER}:${APP_GROUP} config/default_node.conf /etc/dpdk-pot/default_node.conf

# Set the working directory for the application
WORKDIR /opt/dpdk-pot

# Switch to the non-root user for running the application
USER ${APP_USER}

# Define the default entrypoint.
# The actual command, including ALL EAL arguments AND application-specific arguments (like --role),
# will be provided by the 'command:' directive in docker-compose.yaml.
ENTRYPOINT ["/usr/local/bin/dpdk-pot"]

# Default command arguments if the image is run without overrides from docker-compose.
# This is mostly for documentation or standalone basic testing.
# In a real deployment, docker-compose will supply the full command array.
CMD ["--help"]