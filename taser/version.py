# TASER - Testing and security Resource
# Author: m8r0wn
# License: BSD 3-clause
# Source: https://github.com/m8r0wn/taser

from sys import argv
import pkg_resources
from taser.printx import highlight

try:
    VERSION = "v"+pkg_resources.get_distribution('taser').version
except:
    VERSION = ""

AUTHOR = 'm8r0wn'

BANNER = "TASER {} - {}    {}\n".format(VERSION, argv[0].split("/")[-1], highlight('#~{}'.format(AUTHOR), fg='gray'))