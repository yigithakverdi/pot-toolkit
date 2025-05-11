
# Path to your testpmd might vary
# Use core 0 and 1 (-l 0-1), 4 mem channels (-n 4)
# Allocate some host memory (--socket-mem)
# Create a vhost-user device 'eth_vhost0' connected to socket file
# Use a unique file-prefix for host EAL instance
# --no-pci: Don't probe physical PCI devices (unless you bound one and want testpmd to use it)
sudo dpdk-testpmd -l 0-1 -n 4 --socket-mem 1024,0 \
    --vdev 'eth_vhost0,iface=/tmp/vhost-sockets/sock0,queues=1' \
    --file-prefix=host \
    --no-pci -- \
    -i --stats-period 1
    # Add physical port if bound: e.g. add PCI address 0000:00:1f.6 if bound
    # Add testpmd parameters like --portmask=0x1 if using physical port 0