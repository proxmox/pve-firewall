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
    ifconfig "${IF_VETH_BRIDGETO}" up || exit 1
    ip link add name "${IFACE}" type veth peer name "${IFACE}peer" || exit 1
    ip link set "${IFACE}peer" up || exit 1
    brctl addif "${IF_VETH_BRIDGETO}" "${IFACE}peer" || exit 1
elif [ "${MODE}" = "stop" ]; then
    brctl delif "${IF_VETH_BRIDGETO}" "${IFACE}peer"
    ip link set "${IFACE}peer" down || exit 1
    ip link del "${IFACE}" || exit 1
fi

exit 0
