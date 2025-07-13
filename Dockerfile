# Dockerfile for the dpdk-pot application
FROM yigithak/dpdk-pot-base:latest

ARG APP_HOME=/opt/dpdk-pot
ARG BINARY_NAME=dpdk-pot
ARG BINARY_SOURCE_PATH=./build

COPY ${BINARY_SOURCE_PATH}/${BINARY_NAME} /usr/local/bin/${BINARY_NAME}

RUN chmod +x /usr/local/bin/${BINARY_NAME}

WORKDIR ${APP_HOME}

ENTRYPOINT ["/usr/local/bin/dpdk-pot --help"]
CMD ["--help"]