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
    
    case "$PHASE" in
        pre-up)
 
	    test -d "/sys/class/net/${IF_VETH_BRIDGETO}" || ifup "${IF_VETH_BRIDGETO}" || exit 1
	    ip link add name "${IFACE}" type veth peer name "${IFACE}peer" || exit 1
	    ip link set "${IFACE}peer" up || exit 1
	    brctl addif "${IF_VETH_BRIDGETO}" "${IFACE}peer" || exit 1
	    ;;

        post-up)
	    test -n "${IF_VETH_MASQUERADE}" || exit 0
	    if [ -n "${IF_ADDRESS}" -a -n "${IF_NETMASK}" ]; then 
		iptables -t raw -A PREROUTING -s "${IF_ADDRESS}/${IF_NETMASK}" -i "${IF_VETH_BRIDGETO}" -j CT --zone 1
		iptables -t raw -A PREROUTING -d "${IF_ADDRESS}/${IF_NETMASK}" -i  "${IF_VETH_BRIDGETO}" -j CT --zone 1
		iptables -t nat -A POSTROUTING -s "${IF_ADDRESS}/${IF_NETMASK}" -o  "${IF_VETH_MASQUERADE}"  -j MASQUERADE
	    else
		echo "unable to setup VETH_MASQUERADE - no address/network"
		exit 0
	    fi
	    ;;
    esac
  
elif [ "${MODE}" = "stop" ]; then

    case "$PHASE" in
        post-down)
  
	    brctl delif "${IF_VETH_BRIDGETO}" "${IFACE}peer"
	    ip link set "${IFACE}peer" down || exit 1
	    ip link del "${IFACE}" || exit 1
	    ;;

        pre-down)
	    test -n "${IF_VETH_MASQUERADE}" || exit 0
	    if [ -n "${IF_ADDRESS}" -a -n "${IF_NETMASK}" ]; then 
		iptables -t raw -D PREROUTING -s "${IF_ADDRESS}/${IF_NETMASK}" -i "${IF_VETH_BRIDGETO}" -j CT --zone 1
		iptables -t raw -D PREROUTING -d "${IF_ADDRESS}/${IF_NETMASK}" -i  "${IF_VETH_BRIDGETO}" -j CT --zone 1
		iptables -t nat -D POSTROUTING -s "${IF_ADDRESS}/${IF_NETMASK}" -o  "${IF_VETH_MASQUERADE}"  -j MASQUERADE
	    fi
	    ;;

    esac

fi

exit 0
