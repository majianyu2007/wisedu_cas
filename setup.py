"""Legacy setuptools entry point.

This file exists for compatibility with older tooling that still invokes
`python setup.py ...`. Modern builds should use PEP 517 via `pyproject.toml`.
"""

from setuptools import setup


if __name__ == "__main__":
    setup()
