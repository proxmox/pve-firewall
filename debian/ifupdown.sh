#!/bin/sh

# create a VETH device and plug it into bridge ${IF_VETH_BRIDGETO}

if [ -z "${IF_VETH_BRIDGETO}" ]; then
    exit 0
fi

if [ ! -x /sbin/brctl ]
then
    exit 0
fi

if [ "${MODE}" = "start" ]; then
    ifconfig "${IF_VETH_BRIDGETO}" up
    ip link add name "${IFACE}" type veth peer name "${IFACE}peer"
    ip link set "${IFACE}peer" up
    brctl addif "${IF_VETH_BRIDGETO}" "${IFACE}peer"
elif [ "${MODE}" = "stop" ]; then
    brctl delif "${IF_VETH_BRIDGETO}" "${IFACE}peer"
    ip link set "${IFACE}peer" down
    ip link del "${IFACE}"
fi

exit 0
