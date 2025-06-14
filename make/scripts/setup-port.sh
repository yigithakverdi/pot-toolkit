#!/bin/bash

# ==============================================================================
# DPDK Environment Setup Script for EC2
# ==============================================================================
# This script automates the setup of a network interface for DPDK use
# after a system reboot. It handles:
#   1. Mounting HugePages.
#   2. Loading the VFIO-PCI driver.
#   3. Binding the specified network interface to the driver.
#
# Must be run with sudo or as root.
# ==============================================================================

# --- Configuration ---
# The network interface you want to dedicate to DPDK (e.g., ens6, eth1)
DPDK_IFACE="ens6"

# The DPDK driver to use. 'vfio-pci' is recommended.
DPDK_DRIVER="vfio-pci"

# The full path to the dpdk-devbind tool.
# This should be correct if you installed DPDK to /usr/local.
DEV_BIND_TOOL="/usr/local/bin/dpdk-devbind.py"


# --- Helper Functions ---
info() {
    echo "[INFO] $1"
}

error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}


# --- Main Execution ---
main() {
    # 1. Check for Root Privileges
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "This script must be run as root or with sudo."
    fi

    info "Starting DPDK environment setup..."

    # 2. Check for dpdk-devbind tool
    if [ ! -x "$DEV_BIND_TOOL" ]; then
        error_exit "DPDK devbind tool not found or not executable at '$DEV_BIND_TOOL'"
    fi

    # 3. Configure HugePages
    # Your /etc/sysctl.conf change reserves the pages, but we need to ensure
    # the hugetlbfs filesystem is mounted.
    info "Configuring HugePages..."
    if ! mount | grep -q 'hugetlbfs on /mnt/huge'; then
        info "Mounting hugetlbfs on /mnt/huge..."
        mkdir -p /mnt/huge
        mount -t hugetlbfs nodev /mnt/huge
    else
        info "HugePages filesystem already mounted."
    fi
    info "$(grep HugePages /proc/meminfo)"
    
    # ONE-TIME ACTION: To make the mount persistent across reboots, add it to /etc/fstab
    if ! grep -q '/mnt/huge' /etc/fstab; then
        info "To make HugePages mount persistent, run this command once:"
        echo 'echo "hugetlbfs /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab'
    fi

    # 4. Load VFIO-PCI Driver
    info "Loading DPDK driver: $DPDK_DRIVER"
    if ! lsmod | grep -q "$DPDK_DRIVER"; then
        modprobe "$DPDK_DRIVER"
        # This workaround enables VFIO without a real IOMMU (common on some setups)
        # The "proper" fix is enabling IOMMU in GRUB, but this ensures it works.
        if [ -f "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode" ]; then
             echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
             info "Enabled 'enable_unsafe_noiommu_mode' for VFIO."
        fi
    else
        info "Driver '$DPDK_DRIVER' already loaded."
    fi


    # 5. Bind the Network Interface to the DPDK Driver
    info "Binding network interface '$DPDK_IFACE' to driver '$DPDK_DRIVER'..."
    
    # Check if the interface exists
    if ! ip link show "$DPDK_IFACE" &>/dev/null; then
        error_exit "Network interface '$DPDK_IFACE' does not exist."
    fi

    # Get the PCI address of the interface
    PCI_ADDR=$(ethtool -i "$DPDK_IFACE" | grep 'bus-info:' | awk '{print $2}')
    if [ -z "$PCI_ADDR" ]; then
        error_exit "Could not determine PCI address for '$DPDK_IFACE'."
    fi
    info "Found '$DPDK_IFACE' at PCI address: $PCI_ADDR"

    # Check if the device is already bound to the DPDK driver
    CURRENT_DRIVER=$("$DEV_BIND_TOOL" --status | grep "$PCI_ADDR" | awk '{print $3}' | sed "s/drv=//")

    if [ "$CURRENT_DRIVER" == "$DPDK_DRIVER" ]; then
        info "Interface '$DPDK_IFACE' ($PCI_ADDR) is already bound to '$DPDK_DRIVER'."
    else
        info "Interface is currently using driver '$CURRENT_DRIVER'. Binding to '$DPDK_DRIVER'..."
        ip link set "$DPDK_IFACE" down
        "$DEV_BIND_TOOL" --bind="$DPDK_DRIVER" "$PCI_ADDR"
    fi

    # 6. Final Status Check
    info "Setup complete. Final status:"
    echo "--------------------------------"
    "$DEV_BIND_TOOL" --status
    echo "--------------------------------"
}

# Run the main function
main "$@"
