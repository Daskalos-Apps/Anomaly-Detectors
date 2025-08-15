#!/usr/bin/env python3
"""
Setup script for Enhanced HTTP Anomaly Detection
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="enhanced-http-anomaly-detection",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Enhanced HTTP Anomaly Detection with Federated Learning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/Dask-AD",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.4.1",
        ],
        "viz": [
            "matplotlib>=3.7.2",
            "seaborn>=0.12.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "enhanced-detector=ai_detection_engine.enhanced_detector:main",
            "http-extractor=ai_detection_engine.http_feature_extractor:main",
            "benchmark-detector=benchmark:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.conf", "*.yml", "*.yaml", "*.json"],
    },
    zip_safe=False,
)