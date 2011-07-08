# -*- coding: utf-8 -*-
from setuptools import setup
from glob import glob

setup(name="haystack",
    version="0.8",
    description="Search C Structures in a process' memory",
    long_description=open('README').read(),

    url="http://packages.python.org/haystack/",
    download_url="http://github.com/trolldbois/python-haystack/tree/master",
    license='GPL',
    classifiers=[
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Environment :: X11 Applications :: Qt",        
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=['memory','analysis','forensics','struct','ptrace'],
    author="Loic Jaquemet",
    author_email="loic.jaquemet+python@gmail.com",
    packages = ['haystack','haystack.gui'],
    scripts = ['scripts/haystack', 'scripts/haystack-gui', 'scripts/haystack-dump'],
    install_requires = ["python-ptrace","argparse"],
)


