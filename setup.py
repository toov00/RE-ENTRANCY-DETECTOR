from setuptools import setup, find_packages

setup(
    name="reentrancy-detector",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "reentrancy-detector=src.cli:main",
        ],
    },
    python_requires=">=3.8",
    description="Static analysis tool for detecting reentrancy vulnerabilities in Solidity",
)
