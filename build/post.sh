#! /usr/bin/env bash

set -e

rm -rf build
rm -f autogen.sh
make -f Makefile.in srcdir=. tls.tcl.h

exit 0
