#!/bin/bash

# Run this in parallel with:
# $ cargo test --target x86_64-fortanix-unknown-sgx --release -- --nocapture --ignored echo

for i in $(seq 1 100); do
    echo $i
    telnet localhost 7799 < /dev/zero &> /dev/null &
    sleep 0.01
done

sleep 10s
kill $(jobs -p)
wait
