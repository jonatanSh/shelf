from setuptools import find_packages, setup
import os
import sys

version = int(sys.version[0])
if version == 2:
    raise Exception("Only supported in python3 to force install use --force-disable-py2-check")
README = 'UNDEFINED'
try:
    with open(os.path.join('..', '..', os.path.dirname(__file__), 'docs', 'shelf_loader.md'), 'r') as fp:
        README = str(fp.read())
except Exception as e:
    print("Readme error: {}".format(e))

setup(
    name='shelf_loader',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'py_shelf',
        'capstone',
    ],
    license='MIT License',
    description='The loader of the py_shelf package',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://github.com/jonatanSh/shelf',
    author='Jonathan Shimon',
    author_email='jonatanshimon@gmail.com',
    package_data={'': ['*.shellcode']}

)
