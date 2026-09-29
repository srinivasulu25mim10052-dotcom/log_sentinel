#!/usr/bin/env python3
"""
Setup script for LogSentinel.
Allows installation via: python -m pip install -e .
"""

from setuptools import setup, find_packages

setup(
    name="logsentinel",
    version="1.0.0",
    description="Automated Server Log Incident Diagnostics & Threat Detection Engine",
    author="LogSentinel Team",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "logsentinel=sentinel.cli:main",
            "log-sentinel=sentinel.cli:main",
        ],
    },
)
