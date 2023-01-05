# License: BSD 3-clause
# Source: https://github.com/m8sec/taser

from sys import argv
import pkg_resources
from taser.printx import highlight

try:
    VERSION = pkg_resources.get_distribution('taser').version
except:
    VERSION = "n/a"


AUTHOR = 'm8sec'
BANNER = "TASER v{} - {}    {}\n".format(VERSION, argv[0].split("/")[-1], highlight('#~{}'.format(AUTHOR), fg='gray'))