from pathlib import Path
from setuptools import find_packages, setup

BASE_DIR = Path(__file__).resolve().parent
README = BASE_DIR / "README.md"

INSTALL_REQUIRES = [
    "beautifulsoup4",
    "cryptography",
    "dnspython",
    "ipparser>=1.0.0",
    "lxml",
    "ntlm-auth",
    "requests",
    "requests-file",
    "requests-ntlm",
]

EXTRAS_REQUIRE = {
    "browser": ["selenium"],
    "exp": ["pyopenssl", "scapy"],
}

setup(
    name="taser",
    version="0.5.0",
    author="m8sec",
    description="Security resource and abstraction library",
    long_description=README.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    url="https://github.com/m8sec/taser",
    license="BSD-3-Clause",
    python_requires=">=3.9",
    packages=find_packages(include=[
        "taser", "taser.*"
    ]),
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
    ],
)
