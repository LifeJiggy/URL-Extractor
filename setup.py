#!/usr/bin/env python3
"""
Setup script for URL Extractor - PyPI package
"""

from setuptools import setup, find_packages
import os

# Read README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="url-extractor",
    version="5.0.0",
    author="ArkhAngelLifeJiggy",
    author_email="Bloomtonjovish@gmail.com",
    description="A powerful, pure Python tool for extracting all URLs and extensions from target websites",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LifeJiggy/URL-Extractor",
    packages=find_packages(),
    py_modules=["url_extractor"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="url extraction web scraping security reconnaissance wayback commoncrawl javascript analysis",
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "url-extractor=url_extractor:main",
            "urlextractor=url_extractor:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/LifeJiggy/URL-Extractor/issues",
        "Source": "https://github.com/LifeJiggy/URL-Extractor",
        "Documentation": "https://github.com/LifeJiggy/URL-Extractor#readme",
    },
    include_package_data=True,
    zip_safe=False,
)