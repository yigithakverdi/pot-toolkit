# Dockerfile (Main Application Image for dpdk-pot)
# Builds the generic application image that can run as ingress, transit, or egress.

# Use an ARG to easily reference the base image name/tag
ARG BASE_IMAGE=photon-dpdk-base:latest
FROM ${BASE_IMAGE}

# Define user/group again for clarity and potential use in COPY/RUN
ARG APP_USER=dpdk
ARG APP_GROUP=dpdk

# Create application-specific directories needed at runtime.
# - /opt/dpdk-pot: Working directory, scripts can go here.
# - /etc/dpdk-pot/mounted_config: Where node-specific generated configs will be mounted.
# - /etc/dpdk-pot/defaults: Optional location for default configs baked into the image.
# - /var/log/dpdk-pot: For application logs (ensure host mounts a volume here if persistence is needed).
RUN mkdir -p /opt/dpdk-pot/scripts \
             /etc/dpdk-pot/mounted_config \
             /etc/dpdk-pot/defaults \
             /var/log/dpdk-pot && \
    chown -R ${APP_USER}:${APP_GROUP} /opt/dpdk-pot \
                                      /etc/dpdk-pot \
                                      /var/log/dpdk-pot

# Copy the single compiled DPDK application binary from your build context.
# Assumes your build process produces './build/bin/dpdk-pot'.
COPY --chown=${APP_USER}:${APP_GROUP} build/dpdk-pot /usr/local/bin/dpdk-pot

# Copy any common helper scripts from your build context (optional)
# Example: COPY --chown=${APP_USER}:${APP_GROUP} scripts/common/* /opt/dpdk-pot/scripts/

# Copy any default configuration files as fallbacks (optional)
# Example: COPY --chown=${APP_USER}:${APP_GROUP} config/default_node.conf /etc/dpdk-pot/defaults/

# Set the default working directory inside the container
WORKDIR /opt/dpdk-pot

# Switch to the non-root user to run the application
USER ${APP_USER}

# Define the application binary as the entrypoint.
# All arguments (EAL + App specific) will be provided by the 'command:'
# directive in the docker-compose.yaml file.
ENTRYPOINT ["/usr/local/bin/dpdk-pot"]

# Define a default command (e.g., show help) if the image is run standalone
# without arguments from docker-compose. This will be overridden by docker-compose.
CMD ["--help"]