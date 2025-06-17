#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later

declare -rA bpf_maps=(
    [pid]="netstack_pidfil"
    [iface]="netstack_ifinde"
    [cgroup]="netstack_cgroup"
)

declare -rA key_converters=(
    [pid]=pid_to_bpftool
    [iface]=iface_to_bpftool
    [cgroup]=cgroup_to_bpftool
)

print_usage()
{
    echo "usage: $0 TYPE val1 [val2 val3 val4...]"
    echo "TYPE: { $(echo "${!bpf_maps[@]}" | tr ' ' '\|') }"
}

pid_to_bpftool()
{
    local val="$1"

    uint_to_bpftool_u32 "$val"
}

# Supports ifname or ifindex
iface_to_bpftool()
{
    local val="$1"

    if ! is_uint "$val"; then
        val="$(ifname_to_idx "$val")"
    fi

    uint_to_bpftool_u32 "$val"
}

# Supports full cgroup path or direct cgroup id (inode)
cgroup_to_bpftool()
{
    local val="$1"

    if ! is_uint "$val"; then
        val="$(cgroup_path_to_id "$val")"
    fi

    uint_to_bpftool_u64 "$val"
}

is_uint()
{
    local val="$1"

    [[ "$val" == +([0-9]) ]]
}

ifname_to_idx()
{
    local ifname="$1"
    local ifindex=0

    ifindex="$(ip address show "$ifname" | grep "[0-9][0-9]*: ${ifname}.*: <")"
    ifindex="${ifindex%%:*}"

    if [[ -z "$ifindex" ]]; then
        return 1
    fi

    echo "$ifindex"
}

cgroup_path_to_id()
{
    local cpath="$1"

    stat -L -c '%i' "$(realpath "$cpath")"
}

# When providing keys/values to bpftool map update, it basically wants one
# argument for each byte in the key/value. So if you have a u32 key (as in any
# array map) and you want to update key 1234, then you will have to provide
# key 0xd2 0x04 0x00 0x00 (1234 in hex split up as the 4 bytes in a u32 in
# little-endian order). These helpers assume you're on a little endian machine.
uint_to_bpftool_u32()
{
    local val="$1"

    printf "0x%02x 0x%02x 0x%02x 0x%02x\n" \
           $((val & 0xff)) $(((val >> 8) & 0xff)) $(((val >> 16) & 0xff)) $(((val >> 24) & 0xff))
}

uint_to_bpftool_u64()
{
    local val="$1"

    printf "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n" \
           $((val & 0xff)) $(((val >> 8) & 0xff)) $(((val >> 16) & 0xff)) $(((val >> 24) & 0xff)) \
           $(((val >> 32) & 0xff)) $(((val >> 40) & 0xff)) $(((val >> 48) & 0xff)) $(((val >> 56) & 0xff))
}

add_to_filter_map()
{
    local map="$1"
    local key="$2"

    # All the filter maps use a u64 as value
    # Set the value to 1 to indicate that the key should be included in the filter
    bpftool map update name "$map" key $key value $(uint_to_bpftool_u64 1)
}

if (( $# < 2 )); then
    print_usage
    exit 1
fi

type=$1
if [[ -z "${bpf_maps[$type]}" ]]; then
    echo "Error: unrecognized type $type, must be one of: ${!bpf_maps[*]}"
    exit 1
fi

if [ $(printf '\1' | od -dAn) -ne 1 ]; then
    echo "Only little-endian systems supported"
    exit 1
fi

map=${bpf_maps[$type]}
converter=${key_converters[$type]}

for val in "${@:2}"; do
    key=$($converter "$val")
    if ! add_to_filter_map "$map" "$key"; then
        echo "Error adding $val ($key) to map $map"
        exit 1
    fi
done
