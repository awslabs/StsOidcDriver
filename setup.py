from setuptools import setup, find_packages

setup(
    name="sts_oidc_driver", 
    version="1.0.0",
    py_modules=["stsoidcdriver"],
    install_requires=[
        "requests~=2.32.3",
        "bottle~=0.13.2",
        "boto3~=1.37.2",
        "pyjwt~=2.10.1"
    ],
    entry_points={
        "console_scripts": [
            "stsoidcdriver=stsoidcdriver:main",  
        ],
    },
    author="Liam Wadman",
    author_email="liwadman@amazon.com",
    description="A utility to sign into the AWS CLI with STS using OIDC/OAuth",
    url="https://github.com/awslabs/StsOidcDriver",  
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)