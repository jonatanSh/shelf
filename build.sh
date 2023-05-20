#!/usr/bin/env bash
set -e
if [ "$1" = "shelf" ]; then
    cd mini_loaders && python compile.py --action make clean
    cd ..
    # building current version
    python3 setup.py sdist

    # installing latest version
    echo built: $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")

fi

if [ "$1" = "shelf_loader" ]; then
    make shellcode_loader
    cd shellcode_loader
    python3 setup.py sdist
    # installing latest version
    echo built: $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
    cd ..
fi


