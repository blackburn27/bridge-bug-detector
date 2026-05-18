from setuptools import setup, find_packages

setup(
    name="bridge-bug-detector",
    version="0.1.0",
    packages=find_packages(),
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "bridge-detect=bridge_detector.cli:main",
        ],
    },
)
