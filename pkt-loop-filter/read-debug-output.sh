#!/bin/sh

set -o errexit

TRACE_ACTIVE=$(cat /sys/kernel/debug/tracing/tracing_on)

if [ "$TRACE_ACTIVE" -ne "1" ]; then
    echo "Kernel tracing disabled, enabling"
    echo 1 > /sys/kernel/debug/tracing/tracing_on
fi

echo "Reading trace pipe, ^C to exit"
cat /sys/kernel/debug/tracing/trace_pipe
