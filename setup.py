from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="snyk-sast-tool",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive tool for managing Snyk SAST settings and projects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/snyk-sast-tool",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests>=2.31.0',
        'pandas>=2.0.0',
        'openpyxl>=3.1.0',
        'typer>=0.9.0',
        'rich>=13.0.0',
    ],
    entry_points={
        'console_scripts': [
            'snyk-sast-tool=snyk_sast_tool.cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
