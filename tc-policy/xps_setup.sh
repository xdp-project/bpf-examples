#!/bin/bash
#

function usage() {
    echo "Change setting of XPS txq to CPU mapping via files"
    echo " /sys/class/net/DEV/queues/tx-*/xps_cpus "
    echo ""
    echo "Usage: $0 [-h] --dev ethX --txq N --cpu N"
    echo "  -d | --dev     : (\$DEV)       Interface/device (required)"
    echo "  --default      : (\$DEFAULT)   Setup 1:1 mapping TXQ-to-CPU"
    echo "  --disable      : (\$DISABLE)   Disable XPS via mask 0x00"
    echo "  --list         : (\$LIST)      List current setting"
    echo "  --txq N        : (\$TXQ)       Select TXQ"
    echo "  --cpu N        : (\$CPU)       Select CPU that use TXQ"
    echo "  -v | --verbose : (\$VERBOSE)   verbose"
    echo ""
}

## -- General shell logging cmds --
function err() {
    local exitcode=$1
    shift
    echo -e "ERROR: $@" >&2
    exit $exitcode
}

function info() {
    if [[ -n "$VERBOSE" ]]; then
	echo "# $@"
    fi
}

# Convert a mask to a list of CPUs this cover
function mask_to_cpus() {
    local mask=$1
    local cpu=0

    printf "CPUs in MASK=0x%02X =>" $mask
    if [[ $mask == 0 ]]; then
	echo " disabled"
    fi
    while [ $mask -gt 0 ]; do
	if [[ $((mask & 1)) -eq 1 ]]; then
	    echo -n " cpu:$cpu"
	fi
	let cpu++
	let mask=$((mask >> 1))
    done
}

function sorted_txq_xps_cpus() {
    local queues=$(ls /sys/class/net/$DEV/queues/tx-*/xps_cpus | sort --field-separator='-' -k2n)
    echo $queues
}

function list_xps_setup() {
    local txq=0
    local mqleaf=0
    for xps_cpus in $(sorted_txq_xps_cpus); do
	let mqleaf++
	mask=$(cat $xps_cpus)
	value=$((0x$mask))
	#echo MASK:0x$mask
	txt=$(mask_to_cpus $value)
	echo "NIC=$DEV TXQ:$txq (MQ-leaf :$mqleaf) use $txt"
	let txq++
    done
}

function cpu_to_mask() {
    local cpu=$1
    printf "%X" $((1 << $cpu))
}

# Setup TXQ to only use a single specific CPU
function xps_txq_to_cpu() {
    local txq=$1
    local cpu=$2
    local mask=0
    if [[ "$DISABLE" != "yes" ]]; then
	mask=$(cpu_to_mask $cpu)
    fi
    local txq_file=/sys/class/net/$DEV/queues/tx-$txq/xps_cpus

    if [[ -e "$txq_file" ]]; then
	echo $mask > $txq_file
    fi
}

function xps_setup_1to1_mapping() {
    local cpu=0
    local txq=0
    for xps_cpus in $(sorted_txq_xps_cpus); do

	if [[ "$DISABLE" != "yes" ]]; then
	    # Map the TXQ to CPU number 1-to-1
	    mask=$(cpu_to_mask $cpu)
	else
	    # Disable XPS on TXQ
	    mask=0
	fi

	echo $mask > $xps_cpus
	info "NIC=$DEV TXQ:$txq use CPU $cpu (MQ-leaf :$mqleaf)"
	let cpu++
	let txq++
    done
}

# Using external program "getopt" to get --long-options
OPTIONS=$(getopt -o ld: \
    --long list,default,disable,dev:,txq:,cpu: -- "$@")
if (( $? != 0 )); then
    usage
    err 2 "Error calling getopt"
fi
eval set -- "$OPTIONS"

##  --- Parse command line arguments / parameters ---
while true; do
    case "$1" in
        -d | --dev ) # device
          export DEV=$2
	  info "Device set to: DEV=$DEV" >&2
	  shift 2
          ;;
        -v | --verbose)
          export VERBOSE=yes
          # info "Verbose mode: VERBOSE=$VERBOSE" >&2
	  shift
          ;;
        --list )
	  info "Listing --list" >&2
	  export LIST=yes
	  shift 1
          ;;
        --default )
	  info "Setup default 1-to-1 mapping TXQ-to-CPUs" >&2
	  export DEFAULT=yes
	  shift 1
          ;;
        --disable )
	  info "Disable XPS via mask 0x00" >&2
	  export DISABLE=yes
	  shift 1
          ;;
        --txq )
          export TXQ=$2
	  info "Selected: TXQ=$TXQ" >&2
	  shift 2
          ;;
        --cpu )
          export CPU=$2
	  info "Selected: CPU=$CPU" >&2
	  shift 2
          ;;
	-- )
	  shift
	  break
	  ;;
        -h | --help )
          usage;
	  exit 0
	  ;;
	* )
	  shift
	  break
	  ;;
    esac
done

if [ -z "$DEV" ]; then
    usage
    err 2 "Please specify device"
fi

if [[ -n "$TXQ" ]]; then
    if [[ -z "$CPU" && -z "$DISABLE" ]]; then
	err 4 "CPU also needed when giving TXQ:$TXQ (or --disable)"
    fi
    xps_txq_to_cpu $TXQ $CPU
fi

if [[ -n "$DEFAULT" ]]; then
    xps_setup_1to1_mapping
fi

if [[ "$DISABLE" == "yes" ]]; then
    if [[ -z "$DEFAULT" && -z "$TXQ" ]]; then
	err 5 "Use --disable together with --default or --txq"
    fi
fi

if [[ -n "$LIST" ]]; then
    list_xps_setup
fi
