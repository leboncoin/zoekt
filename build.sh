#!/bin/bash

# this script packages up all the binaries, and a script (deploy.sh)
# to twiddle with the server and the binaries

set -ex

set -u

out=zoekt-bin
mkdir -p "${out}"

while IFS= read -r -d '' d; do
  go build \
    -tags netgo \
    -ldflags "-X github.com/sourcegraph/zoekt/index.Version=dev" \
    -o "${out}/$(basename "$d")" \
    "github.com/sourcegraph/zoekt/$d"
done < <(find cmd/ -maxdepth 1 -type d -print0)

chmod 755 "${out}"/*
