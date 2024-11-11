#!/bin/bash

go build -C src -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -o ../bin/x86_64/ubuntu_24.04/mtls-persona .
ln -sf "$(pwd)/bin/x86_64/ubuntu_24.04/mtls-persona" /usr/local/bin/mtls-persona
