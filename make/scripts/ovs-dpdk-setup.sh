# --- Variables ---
OVS_BRIDGE="br-dpdkpot"
SOCKET_DIR="/var/run/openvswitch" # OVS default socket location

# Socket paths OVS will create
SOCK_INGRESS_OUT="${SOCKET_DIR}/vhu_ingress_out.sock"
SOCK_TRANSIT1_IN="${SOCKET_DIR}/vhu_transit1_in.sock"
SOCK_TRANSIT1_OUT="${SOCKET_DIR}/vhu_transit1_out.sock"
SOCK_EGRESS_IN="${SOCKET_DIR}/vhu_egress_in.sock"

# Corresponding OVS port names
OVS_PORT_INGRESS_OUT="vhu-ing-out"
OVS_PORT_TRANSIT1_IN="vhu-t1-in"
OVS_PORT_TRANSIT1_OUT="vhu-t1-out"
OVS_PORT_EGRESS_IN="vhu-egr-in"

# --- OVS Setup ---
# 1. Create Bridge (clean up if needed)
sudo ovs-vsctl --if-exists del-br $OVS_BRIDGE
sudo ovs-vsctl add-br $OVS_BRIDGE -- set bridge $OVS_BRIDGE datapath_type=netdev

# 2. Create vhost-user ports (OVS acts as server)
sudo ovs-vsctl add-port $OVS_BRIDGE $OVS_PORT_INGRESS_OUT -- set Interface $OVS_PORT_INGRESS_OUT type=dpdkvhostuser options:vhost-server-path=$SOCK_INGRESS_OUT
sudo ovs-vsctl add-port $OVS_BRIDGE $OVS_PORT_TRANSIT1_IN -- set Interface $OVS_PORT_TRANSIT1_IN type=dpdkvhostuser options:vhost-server-path=$SOCK_TRANSIT1_IN
sudo ovs-vsctl add-port $OVS_BRIDGE $OVS_PORT_TRANSIT1_OUT -- set Interface $OVS_PORT_TRANSIT1_OUT type=dpdkvhostuser options:vhost-server-path=$SOCK_TRANSIT1_OUT
sudo ovs-vsctl add-port $OVS_BRIDGE $OVS_PORT_EGRESS_IN -- set Interface $OVS_PORT_EGRESS_IN type=dpdkvhostuser options:vhost-server-path=$SOCK_EGRESS_IN

# 3. Add Flow Rules for the pipeline (Ingress -> T1 -> Egress)
sudo ovs-ofctl del-flows $OVS_BRIDGE # Clear old flows
sudo ovs-ofctl add-flow $OVS_BRIDGE "in_port=$OVS_PORT_INGRESS_OUT,actions=output:$OVS_PORT_TRANSIT1_IN"
sudo ovs-ofctl add-flow $OVS_BRIDGE "in_port=$OVS_PORT_TRANSIT1_OUT,actions=output:$OVS_PORT_EGRESS_IN"
sudo ovs-ofctl add-flow $OVS_BRIDGE "priority=0,actions=drop" # Default drop

# 4. Verify
sudo ovs-vsctl show
sudo ovs-ofctl dump-flows $OVS_BRIDGE
ls -l /var/run/openvswitch/ # Check socket files exist