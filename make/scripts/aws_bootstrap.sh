#!/bin/bash
# AWS instance initialization script

# Install dependencies
yum update -y
yum install -y docker git meson numactl-devel

# Configure Docker
systemctl start docker
usermod -aG docker ec2-user

# Clone repo
git clone https://github.com/your/dpdk-pot.git /srv/pot
cd /srv/pot

# Build and deploy
git submodule update --init --recursive
docker compose build
docker compose up -d

# Enable hugepages
sysctl -w vm.nr_hugepages=1024
mount -t hugetlbfs hugetlbfs /dev/hugepages