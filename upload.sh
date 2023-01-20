#!/usr/bin/env bash

# building
./build.sh

# uploading
python3 -m twine upload $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")