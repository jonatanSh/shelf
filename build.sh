#!/usr/bin/env bash
set -e
if [ "$1" = "shelf" ]; then
    cd mini_loaders && python3 compile.py --action make clean
    cd ..
    cd shelf
    # building current version
    python3 setup.py sdist

    # installing latest version
    echo built: $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
    cd ..
fi

if [ "$1" = "shelf_loader" ]; then
    make shellcode_loader
    cd ./shellcode_loader/shelf_loader
    python3 setup.py sdist
    # installing latest version
    echo built: $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")
    cd ..
fi


