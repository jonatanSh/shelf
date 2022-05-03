from setuptools import find_packages, setup
import os

try:
    import pypandoc

    README = pypandoc.convert(os.path.join(os.path.dirname(__file__), 'README.md'), 'rst')
except (ImportError, OSError) as e:
    print("Can't convert readme: {}".format(e))
    README = ""

setup(
    name='elf_to_shellcode',
    version='1.2',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['pyelftools'],
    license='MIT License',
    description='Python package to create shellcdoes from elfs',
    long_description=README,
    url='https://github.com/jonatanSh/elf_to_shellcode',
    author='Jonathan Shimon',
    author_email='jonatanshimon@gmail.com',
    package_data={'': ['*.shellcode']}

)