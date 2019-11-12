#! /usr/bin/env bash

./autogen.sh || exit 1
rm -rf aclocal
./build/make-msvc-win || exit 1

exit 0
