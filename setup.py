import os
import re

import setuptools


def get_version() -> str:
    init_path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        "mullvad_wrapper/__init__.py",
    )
    with open(init_path, "r") as fh:
        init_file = fh.read()
    match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", init_file, re.M)
    if not match:
        raise RuntimeError("Cannot find package version")
    return match.group(1)


setuptools.setup(
    name="mullvad-wrapper",
    version=get_version(),
    author="sndv",
    author_email="sndv@mailbox.org",
    description="A mullvad vpn cli wrapper",
    url="https://github.com/sndv/mullvad-wrapper-py",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    packages=["mullvad_wrapper"],
    python_requires=">=3.10",
    install_requires=[
        "python-dateutil>=2.8.2",
    ],
)
