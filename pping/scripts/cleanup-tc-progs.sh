#!/bin/bash

interface=$1

if [[ -z "$interface" ]]; then
    echo "Usage: $0 <interface>"
    exit 0
fi

if [[ ! -e "/sys/class/net/$interface" ]]; then
    echo "$interface is not a valid interface" 1>&2
    exit 1
fi

for trafdir in "ingress" "egress"; do
    prios=$(tc filter show dev "$interface" "$trafdir" | grep pping_tc | cut -f 5 -d ' ')

    while IFS= read -r p || [[ -n "$p" ]]; do
	if [[ "$p" =~ ^[0-9]+ ]]; then
	    tc filter del dev "$interface" "$trafdir" prio "$p"
	fi
    done <<< "$prios"

done
