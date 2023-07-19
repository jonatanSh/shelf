from setuptools import find_packages, setup
import os
import sys
from shelf.__version__ import FULL

disable_checks = '--force-disable-py2-check' in sys.argv

version = int(sys.version[0])
if not disable_checks and version == 2:
    raise Exception("Only supported in python3 to force install use --force-disable-py2-check")
if disable_checks:
    sys.argv.remove('--force-disable-py2-check')
py_specific_req_2 = [
    'lief==0.9',
]
py_specific_req_3 = [
    'lief==0.12.1',
]

py_specific_req = py_specific_req_2
README = "UNDEFINED"
if version >= 3:
    py_specific_req = py_specific_req_3
try:
    with open(os.path.join(os.path.dirname(__file__), '..', 'README.md'), 'r') as fp:
        README = str(fp.read())
except Exception as e:
    print("Readme error: {}".format(e))


def filter_out(p):
    if p.startswith('shellcode_loader') or p.startswith('mini_loaders'):
        return True
    return False


setup(
    name='py_shelf',
    version=FULL,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
                         'pyelftools',
                         'capstone',
                         'py_elf_structs>=1.4.2'
                     ] + py_specific_req,
    license='MIT License',
    description='Python package to create shellcodes from elfs supported arch '
                '(mips, arm (32bit), i386 32bit, i386 64bit, aarch64, RISC-V rv64 P)',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://github.com/jonatanSh/shelf',
    author='Jonathan Shimon',
    author_email='jonatanshimon@gmail.com',
    package_data={'': ['*.shellcode', "*.hooks", "*.json", "*.symbols"]}

)
