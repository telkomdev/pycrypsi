#!/usr/bin/env python

from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (HERE / 'README.md').read_text(encoding='utf-8')

setup(
    name='pycrypsi', 
    version='1.0.0',
    description='pycrypsi (Python Crypto Utility)',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/telkomdev/pycrypsi',
    author='wuriyanto',
    author_email='wuriyanto48@yahoo.co.id',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Environment :: Console',

        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development',
        'Topic :: Utilities',
    ],
    keywords='hashing, hash, digest, aes, rsa, crypto, security',
    packages=find_packages(exclude=['tests*']),
    python_requires='>=3.5',
    project_urls={
        'Bug Reports': 'https://github.com/telkomdev/pycrypsi/issues',
        'Source': 'https://github.com/telkomdev/pycrypsi/',
    },
)