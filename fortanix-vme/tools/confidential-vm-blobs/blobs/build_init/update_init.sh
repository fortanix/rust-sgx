#!/bin/bash

# update the `init` executable stored in the parent directory

script_folder=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

image_name=blobs_all
container_name="${image_name}_extract"
output=$(dirname "$script_folder") #store in parent by default
while [ $# -gt 0 ]; do
    case "$1" in
    --image_name)
        shift
        image_name=$1
        ;;
    --container_name)
        shift
        container_name=$1
        ;;
    --output)
        usage
        exit 0
        ;;
    --*)
        echo "Error: bad option $1"
        exit 1
        ;;
    *)
        echo "Error: bad argument $1"
        exit 1
        ;;
    esac
    shift
done

docker build -t "$image_name" "$script_folder"

docker create --name "$container_name" "$image_name"
docker cp "${container_name}:/blobs/." "$output"
docker rm "$container_name"
