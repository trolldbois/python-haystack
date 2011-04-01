# -*- coding: utf-8 -*-
from setuptools import setup
from glob import glob

setup(name="haystack",
    version="0.4",
    description="Search C Structures in a process' memory",
    long_description=open('README').read(),

    url="http://packages.python.org/haystack/",
    download_url="http://github.com/trolldbois/python-haystack/tree/master",
    license='GPL',
    classifiers=[
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=['memory','analysis','forensics','struct','ptrace'],
    author="Loic Jaquemet",
    author_email="loic.jaquemet+python@gmail.com",
    packages = ['haystack'],
    scripts = ['scripts/haystack'],
    install_requires = ["python-ptrace","argparse"],
)
