from setuptools import find_packages, setup
import os

try:
    with open(os.path.join(os.path.dirname(__file__), 'README.md'), 'rb') as fp:
        README = fp.read()
except:
    print("Readme error")

setup(
    name='elf_to_shellcode',
    version='1.8',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['pyelftools'],
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
