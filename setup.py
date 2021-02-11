from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='taser',
    version='0.3.1',
    author = 'm8r0wn',
    author_email = 'm8r0wn@protonmail.com',
    description = 'Security testing resource library',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/m8r0wn/taser',
    license='BSD 3-clause',
    include_package_data=True,
    packages=find_packages(include=[
        "taser", "taser.*"
    ]),
    package_data={
        '': ['*']
    },
    install_requires=[
        'bs4',
        'dnspython',
        'requests',
        'requests[socks]',
        'requests_ntlm',
        'tldextract',
        'lxml'
    ],
    classifiers = [
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License"
    ],
)
