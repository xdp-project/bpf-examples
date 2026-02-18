#!/bin/bash

# This script configures an environment for testing NAT64.
#
# It requires an existing interface with IPv4 connectivity. The
# interface is moved into a namespace and configured via DHCPv4.  The
# NAT64 BPF program is loaded in the namespace to perform the traffic
# translation. Finally, a veth interface is added into the initial
# namespace; this interface advertises a IPv6 prefix via radvd,
# together with the PREF64 option. Clients can connect to the veth
# interface, reach the NAT64 gateway via IPv6 and use CLAT to access
# the IPv4 Internet.

###############################################################
#                                                   [init ns] #
#         veth0                                               #
#           ^                                                 #
# ----------|------------------------------------------------ #
#           v                                           [ns1] #
#         veth1                              dummy1           #
#    2002:aaaa::1/64    <-- NAT64 -->    100.99.1.1/24        #
#        (radvd)                               ^              #
#                                            NAT44            #
#                                              v              #
#                                            $IFACE           #
#                                         (dhcp client)       #
# ---------------------------------------------|------------- #
#                                              v              #
#                       IPv4 Internet                         #
###############################################################


# The NAT64 prefix to use
PREF64=64:ff9b::/96
#PREF64=2001:db8::/32
#PREF64=2001:db8:100::/40
#PREF64=2001:db8:122::/48
#PREF64=2001:db8:122:300::/56
#PREF64=2001:db8:122:344::/64

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "*** Error: interface not set."
    echo "Run the script as: $0 IFACE"
    echo "IFACE must be an existing interface with IPv4 connectivity. It will be moved into a network namespace and configured with DHCPv4."
    exit 1
fi

require()
{
    if ! command -v "$1" > /dev/null ; then
        echo " *** Error: command '$1' not found"
        exit 1
    fi
}

cleanup()
{
    (
        set +e
        ip netns exec ns1 dhclient -r "$IFACE"
        ip netns del ns1
        ip link del veth0
        pkill -F /tmp/radvd.pid
    )2>/dev/null || :
}

require ip
require radvd
require dhclient

cleanup
trap cleanup EXIT

set -ex

# set up ns1
ip netns add ns1
ip link add veth0 type veth peer name veth1 netns ns1
ip link add dummy1 netns ns1 type dummy

ip -n ns1 link set veth1 up
ip -n ns1 addr add dev veth1 2002:aaaa::1/64
ip -n ns1 link set dummy1 up
ip -n ns1 addr add dev dummy1 100.99.1.1/24
ip netns exec ns1 sysctl -w net.ipv4.ip_forward=1
ip netns exec ns1 iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
ip link set "$IFACE" netns ns1
ip netns exec ns1 dhclient "$IFACE"

# set up radvd
ip netns exec ns1 sysctl -w net.ipv6.conf.all.forwarding=1
cat <<EOF >/tmp/radvd.conf
interface veth1
{
    AdvSendAdvert on;
    MinRtrAdvInterval 30;
    MaxRtrAdvInterval 45;
    prefix 2002:aaaa::/64 {
        AdvOnLink on;
        AdvAutonomous on;
        AdvPreferredLifetime 60;
        AdvValidLifetime 100;
    };

    nat64prefix $PREF64 {
        AdvValidLifetime 60;
    };
};
EOF
ip netns exec ns1 radvd --configtest --config /tmp/radvd.conf
ip netns exec ns1 radvd --config /tmp/radvd.conf --pidfile /tmp/radvd.pid

# set up NAT64 using bpf-examples
ip netns exec ns1 ./nat64 -i veth1 -4 100.99.1.144/28 -6 "$PREF64" -a 2002:aaaa::/64

set +x
echo
echo "NAT64 set up successfully on interface veth0"
echo
read -p "Press enter to end..."

exit 0
