from setuptools import setup, find_packages

setup(
    name="shared",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[],
    author="Karned",
    author_email="<EMAIL>",
    description="Shared FastApi middlewares and decorators",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/karned-kommon/shared",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Framework :: FastAPI",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
)