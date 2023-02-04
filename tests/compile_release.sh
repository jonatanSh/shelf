set -e
cd ../mini_loaders && python compile.py release
cd ../tests && make all -j 16
