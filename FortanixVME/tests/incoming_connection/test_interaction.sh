#!/bin/bash -ex

while [ true ]
do
  echo "Interacting with test"
  curl -k localhost:3400 || true
  sleep 20s
done
