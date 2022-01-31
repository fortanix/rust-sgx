#!/bin/bash -ex

function cleanup {
    killall socat
}

trap cleanup err
trap cleanup exit

socat -v TCP-LISTEN:3080,fork TCP:www.google.com:80
