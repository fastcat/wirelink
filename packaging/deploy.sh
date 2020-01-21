#!/bin/bash

set -xeuo pipefail

cd "$(git rev-parse --show-toplevel)"

make clean
make
make checkinstall

adddebs ./packaging/checkinstall/wirelink*.deb

sudo dpkg --install ./packaging/checkinstall/wirelink*.deb
