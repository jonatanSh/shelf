#!/usr/bin/env bash

# building
./build.sh $@

if [ "$1" = "shelf" ]; then
    python -m twine upload $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ") --verbose
fi

# uploading
if [ "$1" = "shelf_loader" ]; then
  cd shellcode_loader
  python -m twine upload $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ") --verbose
  cd ..
fi