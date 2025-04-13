#!/usr/bin/env bash
set -euo pipefail

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DPDK_VERSION="v24.11"
AWS_INSTANCE_TYPE="c5n.large"  
AWS_SECURITY_GROUP="srv6-pot-sg"
LOG_FILE="${PROJECT_DIR}/deploy.log"

# Environment detection
ENV=${1:-local}
ACTION=${2:-deploy}
NODE_COUNT=${3:-3}

# Initialize logging
exec > >(tee -a "${LOG_FILE}") 2>&1

show_help() {
    echo "Usage: $0 [environment] [action] [node_count]"
    echo "Environments: local | container | aws"
    echo "Actions: deploy | destroy | test | bench"
    echo "Example: $0 container deploy 5"
    exit 1
}

check_dependencies() {
    local deps=("docker" "meson" "git")
    [[ "$ENV" == "aws" ]] && deps+=("aws")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo "Error: $dep required but not found"
            exit 1
        fi
    done
}

setup_local() {
    case "$ACTION" in
        deploy)
            echo "🔧 Local Development Setup"
            git submodule update --init --recursive
            meson setup build --prefix="${PROJECT_DIR}/.local" && ninja -C build
            ;;
        test)
            LD_LIBRARY_PATH="${PROJECT_DIR}/.local/lib" ./build/controller --test
            ;;
        *) echo "Unknown action"; exit 1;;
    esac
}

setup_container() {
    case "$ACTION" in
        deploy)
            echo "🐳 Container Deployment (Nodes: $NODE_COUNT)"
            docker compose build --no-cache
            docker compose up -d --scale middlenode="$NODE_COUNT"
            ;;
        destroy)
            docker compose down -v
            ;;
        test)
            docker compose exec controller ./build/controller --test
            ;;
        bench)
            docker compose exec -T controller ./build/controller --benchmark \
                --nodes "$NODE_COUNT"
            ;;
        *) echo "Unknown action"; exit 1;;
    esac
}

setup_aws() {
    case "$ACTION" in
        deploy)
            echo "AWS Cluster Deployment"
            
            # Create security group if not exists
            if ! aws ec2 describe-security-groups \
                --group-names "$AWS_SECURITY_GROUP" &>/dev/null; then
                aws ec2 create-security-group \
                    --group-name "$AWS_SECURITY_GROUP" \
                    --description "SRv6 POT Cluster"
                aws ec2 authorize-security-group-ingress \
                    --group-name "$AWS_SECURITY_GROUP" \
                    --protocol udp --port 4789 --cidr 0.0.0.0/0
            fi

            # Launch instances
            for ((i=0; i<NODE_COUNT; i++)); do
                aws ec2 run-instances \
                    --image-id ami-0c55b159cbfafe1f0 \
                    --instance-type "$AWS_INSTANCE_TYPE" \
                    --security-groups "$AWS_SECURITY_GROUP" \
                    --user-data "file://${PROJECT_DIR}/aws_bootstrap.sh" \
                    --tag-specifications \
                        "ResourceType=instance,Tags=[{Key=Role,Value=node-$i}]" &
            done
            wait
            
            echo "AWS deployment complete. Allow 2 minutes for initialization."
            ;;
        destroy)
            INSTANCE_IDS=$(aws ec2 describe-instances \
                --filters "Name=tag:Role,Values=node-*" \
                --query "Reservations[].Instances[].InstanceId" \
                --output text)
            aws ec2 terminate-instances --instance-ids $INSTANCE_IDS
            ;;
        test)
            AWS_CONTROLLER=$(aws ec2 describe-instances \
                --filters "Name=tag:Role,Value=node-0" \
                --query "Reservations[0].Instances[0].PublicIpAddress" \
                --output text)
            ssh -i "${AWS_KEY}" ec2-user@${AWS_CONTROLLER} \
                "./controller --test --nodes ${NODE_COUNT}"
            ;;
        *) echo "Unknown action"; exit 1;;
    esac
}

# Main execution
case "$ENV" in
    local) check_dependencies; setup_local ;;
    container) check_dependencies; setup_container ;;
    aws) check_dependencies; setup_aws ;;
    *) show_help ;;
esac

echo "Operation completed successfully"