set -e
cd ../mini_loaders && python compile.py --debug
cd ../tests && make all -j 16
