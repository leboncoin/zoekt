#!/bin/bash

# this script packages up all the binaries, and a script (deploy.sh)
# to twiddle with the server and the binaries

set -ex

set -u

out=zoekt-bin
mkdir -p ${out}

for d in $(find cmd/ -maxdepth 1 -type d)
do
  go build \
    -tags netgo \
    -ldflags "-X github.com/sourcegraph/zoekt.Version=dev" \
    -o ${out}/$(basename $d) \
    github.com/sourcegraph/zoekt/$d
done

chmod 755 ${out}/*
