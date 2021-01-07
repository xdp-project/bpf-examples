#
# Common functions used by scripts in this directory
#  - Depending on bash 3 (or higher) syntax
#
# Author: Jesper Dangaaard Brouer <netoptimizer@brouer.com>
# License: GPLv2

## -- sudo trick --
function root_check_run_with_sudo() {
    # Trick so, program can be run as normal user, will just use "sudo"
    #  call as root_check_run_as_sudo "$@"
    if [ "$EUID" -ne 0 ]; then
	if [ -x $0 ]; then # Directly executable use sudo
	    echo "# (Not root, running with sudo)" >&2
            sudo "$0" "$@"
            exit $?
	fi
	echo "cannot perform sudo run of $0"
	exit 1
    fi
}

## -- General shell logging cmds --
function err() {
    local exitcode=$1
    shift
    echo -e "ERROR: $@" >&2
    exit $exitcode
}

function warn() {
    echo -e "WARN : $@" >&2
}

function info() {
    if [[ -n "$VERBOSE" ]]; then
	echo "# $@"
    fi
}

## -- Wrapper calls for TC --
function _call_tc() {
    local allow_fail="$1"
    shift
    if [[ -n "$VERBOSE" ]]; then
	echo "tc $@"
    fi
    if [[ -n "$DRYRUN" ]]; then
	return
    fi
    $TC "$@"
    local status=$?
    if (( $status != 0 )); then
	if [[ "$allow_fail" == "" ]]; then
	    err 3 "Exec error($status) occurred cmd: \"$TC $@\""
	fi
    fi
}
function call_tc() {
    _call_tc "" "$@"
}
function call_tc_allow_fail() {
    _call_tc "allow_fail" "$@"
}
