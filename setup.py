from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='taser',
    version='0.4.4',
    author='m8sec',
    description='Security Resource library',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/m8sec/taser',
    license='BSD 3-clause',
    include_package_data=True,
    packages=find_packages(include=[
        "taser", "taser.*"
    ]),
    package_data={
        '': ['*']
    },
    install_requires=['beautifulsoup4', 'bs4', 'cryptography', 'dnspython', 'ipparser>=1.0.0', 'lxml', 'ntlm-auth',
                      'requests', 'requests-file', 'requests-ntlm', 'tldextract', 'selenium', 'selenium-wire',
                      'webdriver-manager'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License"
    ]
)
