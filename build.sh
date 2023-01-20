#!/usr/bin/env bash

# building current version
python3 setup.py sdist

# installing latest version
echo built: $(find dist/ -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d" ")