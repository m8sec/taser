# Taser
<p align="center">
    <a href="https://www.twitter.com/m8sec"><img src="https://img.shields.io/badge/Twitter-@m8sec-blue?style=plastic&logo=twitter"/></a>
    &nbsp;    
    <a href="/LICENSE"><img src="https://img.shields.io/badge/License-BSD_3--Clause-green?style=plastic&logo=github"/></a>
    &nbsp;
 </p>


TASER *(Testing and Security Resource)* is an abstraction library used to simplify the process of creating offensive security tooling. The various protocols and classes help streamline development of custom tooling during engagements.

> ⚠ Warning: Taser is a working library and breaking changes may be made.


## Install
### Option 1: Dev Version
Get the latest code (virtual environment recommended):
```bash
git clone https://github.com/m8sec/taser
cd taser
pip install .
```


### Option 2: Stable Release
Install the last stable release directly from PyPi:
```bash
pip3 install taser
```

Optional extras:

- `pip install .[browser]` for Selenium-backed browser and screenshot support
- `pip install .[exp]` for additional experiment/script dependencies


### Troubleshooting
Depending on your setup and install method, you may receive dependency errors. Common options:

1. Install taser from PyPI: `pip3 install taser`
2. Install from the repo: `pip3 install -r requirements.txt && pip3 install .`


## Packaged scripts
Run packaged scripts as modules:

```bash
python -m taser.exp.serviceProbe 10.0.0.0/24 -p 80,443
python -m taser.exp.serviceProbe hosts.txt --screenshot
python -m taser.exp.serviceProbe hosts.txt --screenshot ./screenshots --browser firefox
python -m taser.exp.webProbe hosts.txt --screenshot
```


## Disclaimer
All information is provided for educational purposes ONLY. Never test against systems you don't own or have explicit permission. Use at your own risk - not responsible for impact on future systems. With great power comes great responsibility.
