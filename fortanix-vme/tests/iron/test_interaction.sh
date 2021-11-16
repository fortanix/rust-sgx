#!/bin/bash -ex

while [ true ]
do
  echo "Interacting with test"
  timeout 1s curl -k localhost:3000 || true
  sleep 5s
done
