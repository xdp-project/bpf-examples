#!/bin/bash

MAX_WAIT_ITER=10
pping_path=${1:-"/var/log/pping/pping.out.json"}

pping_folder=$(dirname "$pping_path")
pping_file=$(basename "$pping_path")

if [[ ! -f "$pping_path" ]]; then
    # Nothing to rotate
    exit 0
fi

dailyfolder="$pping_folder/$(date -Idate)"
if ! mkdir -p "$dailyfolder"; then
    exit 1
fi

newplace="$dailyfolder/$pping_file.$(date -Iseconds)"
if ! mv "$pping_path" "$newplace"; then
    exit 1
fi

# Tell ePPing to reopen file
if systemctl is-active --quiet pping.service; then
    systemctl reload pping.service
fi

if [[ -f "$newplace" ]]; then
    for (( i = 0; i < MAX_WAIT_ITER; i++)); do
	if fuser -s "$newplace"; then
	    sleep 1
	else
	    gzip "$newplace"
	    exit $?
	fi
    done
fi

echo "Timed out waiting for $newplace to become unused, unable to compress it" 1>&2
exit 1
