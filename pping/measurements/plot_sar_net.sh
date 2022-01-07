#!/bin/bash

FILENAME=$1
FIGNAME=$2
IFACE=${3:-"ens192"}
IS_TMP_FILE=false

if [[ $FILENAME == *.xz ]]; then
        xz -dk $FILENAME
        IS_TMP_FILE=true
        FILENAME=${FILENAME%.xz}
fi

sadf -g -O skipempty $FILENAME -- -n DEV -n EDEV -n SOFT -n TCP -n ETCP --iface=${IFACE} > ${FIGNAME}.svg

if [[ "$IS_TMP_FILE" == true ]]; then
        rm $FILENAME
fi
