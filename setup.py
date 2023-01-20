from setuptools import find_packages, setup
import os
import sys

version = int(sys.version[0])
if version == 2:
    raise Exception("Only supported in python3")
py_specific_req_2 = [
    'lief==0.9',
]
py_specific_req_3 = [
    'lief==0.12.1',
]

py_specific_req = py_specific_req_2

if version >= 3:
    py_specific_req = py_specific_req_3
try:
    with open(os.path.join(os.path.dirname(__file__), 'README.md'), 'r') as fp:
        README = str(fp.read())
except:
    print("Readme error")

setup(
    name='elf_to_shellcode',
    version='2.2.2',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
                         'pyelftools',
                         'capstone',
                     ] + py_specific_req,
    license='MIT License',
    description='Python package to create shellcdoes from elfs supported arch '
                '(mips, arm (32bit), i386 32bit, i386 64bit, aarch64)',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://github.com/jonatanSh/elf_to_shellcode',
    author='Jonathan Shimon',
    author_email='jonatanshimon@gmail.com',
    package_data={'': ['*.shellcode']}

)
