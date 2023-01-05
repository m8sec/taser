# Taser
<p align="center">
    <a href="https://www.twitter.com/m8sec">
        <img src="https://img.shields.io/badge/Twitter-@m8sec-blue?style=plastic&logo=twitter"/>
    </a>&nbsp;
    <a href="/LICENSE">
        <img src="https://img.shields.io/badge/License-BSD_3--Clause-green?style=plastic&logo=github"/>
    </a>&nbsp;
    <a href="https://github.com/sponsors/m8sec">
        <img src="https://img.shields.io/badge/Sponsor-GitHub-red?style=plastic&logo=github"/>
    </a>&nbsp;
 </p>

TASER *(Testing and Security Resource)* is an abstraction library used to simplify the process of creating offensive security tooling - especially those relating to web or external assessments. It's modular design makes it easy to customize and re-purposed in a variety of scenarios. 

Some core features include:
* Built-in spider class to modify and aid in data collection.
* Rotate User-Agents, proxies, and custom headers per request.
* Automatically detect Windows OS to control ANSI colored output.

> :warning: This is a working library and breaking changes may be made. See the [/examples](/examples) directory for usage

## Install
Get the latest (dev) code and run inside a virtual environment with Poetry:
```bash
git clone https://github.com/m8sec/taser
cd taser
python3 -m poetry install
python3 -m poetry shell
python3 setup.py install
```

Install the last stable release directly from PyPi:
```bash
pip3 install taser
```