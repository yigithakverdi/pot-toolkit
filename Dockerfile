# Dockerfile for the dpdk-pot application
# This file should be in the root of your 'dpdk-pot' project.

# Use your pre-built DPDK base image.
# Replace 'your-dpdk-base-image:latest' with the actual tag of your base image,
# e.g., 'photon-dpdk-base:latest' or 'dpdk-runtime-base:latest'.
FROM ubuntu-dpdk-base:latest

# Arguments for flexibility
ARG APP_USER=dpdk
ARG APP_GROUP=dpdk
ARG APP_HOME=/opt/dpdk-pot
ARG BINARY_NAME=dpdk-pot
ARG BINARY_SOURCE_PATH=./build

# Create application directory and set ownership.
# The base image should have created the APP_USER.
RUN mkdir -p ${APP_HOME}/config/profiles && chown -R ${APP_USER}:${APP_GROUP} ${APP_HOME}

# Copy the compiled DPDK application binary from your project's build directory
# into a standard location within the image.
COPY --chown=${APP_USER}:${APP_GROUP} ${BINARY_SOURCE_PATH}/${BINARY_NAME} /usr/local/bin/${BINARY_NAME}

# Copy default application configuration files.
# The structure config/profiles/*.yaml from your project will be copied to ${APP_HOME}/config/profiles/
COPY --chown=${APP_USER}:${APP_GROUP} config/profiles ${APP_HOME}/config/profiles/

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/${BINARY_NAME}

# Set the working directory for the application
WORKDIR ${APP_HOME}

# Switch to the non-root user
USER ${APP_USER}

# Define the entrypoint for the container.
# The application binary will be executed when the container starts.
ENTRYPOINT ["/usr/local/bin/dpdk-pot"]

# Default command if none is provided to 'docker run' or in docker-compose.
# This allows 'docker run your-image-name' to show help.
# It will be overridden by arguments like '--role ingress ...'
CMD ["--help"]