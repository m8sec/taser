import re
import sys
import base64
import threading
from os import path
from time import sleep
from random import choice
from urllib.parse import quote, unquote
from string import ascii_letters, digits
from datetime import datetime, timedelta


################################
# Self-Manage Execution Timeouts
# Usage:
#   x = Timeout(10)
#   x.start()
#   while x.running:
#       execute_func()
################################
class Timeout(threading.Thread):
    def __init__(self, timeout):
        super().__init__()
        self.timeout = timeout
        self.start_time = datetime.now()
        self.running = True

    def run(self):
        while self.running:
            if (datetime.now() - self.start_time) > timedelta(seconds=self.timeout):
                self.stop()
            sleep(0.05)

    def stop(self):
        self.running = False


################################
# File Utils
################################
def file_read_lines(file):
    with open(file, encoding='utf-8') as handle:
        return [line.strip() for line in handle]


def file_exists(parser, filename, contents=True):
    # Argparse support for accepting & validating files
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return file_read_lines(filename) if contents else filename


def file_collision_check(filename, ext=''):
    # Check filename does not exist or append count
    count = 0
    file_path = path.dirname(filename)
    base_file = remove_special(path.basename(filename))

    # handle ipv4/domain names in filename
    if ipv4check(base_file):
        filename = base_file
    else:
        split_name = base_file.split('.')
        filename = split_name[0]
        ext = split_name[-1] if len(split_name) > 1 and not split_name[-1].endswith(('com', 'net', 'org', 'me')) else ext

    # Iterate to amend filename if duplicates found
    tmp = path.join(file_path, f'{filename}.{ext}')
    while path.exists(tmp):
        count += 1
        tmp = path.join(file_path, f'{filename}-{count}.{ext}')
    return tmp


def remove_special(value):
    # Remove special chars from filenames for saving
    data = ''
    for x in value:
        if x not in '<>\'"\\$&{}|^`~!;':
            data += x
    return data


################################
# Sort/Organize Argparse Inputs
################################
def delimiter2list(value, delim=","):
    return [x.strip() for x in value.split(delim)] if value else []


def unique_values(values):
    seen = set()
    ordered = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def delimiter2dict(value, delim_one=";", delim_two=":"):
    x = {}
    for item in value.split(delim_one):
        if item:
            sp = item.split(delim_two)
            x[sp[0].strip()] = delim_two.join(sp[1:]).strip()
    return x


def ranger(size_input):
    # Takes comma separated or range of number inputs and returns a single list to iterate over.
    t = []
    for x in delimiter2list(size_input):
        if '-' in x:
            start, stop = map(int, x.split('-'))
            t.extend(range(start, stop + 1))
        else:
            t.append(int(x))
    return t


def val2list(value, delimiter=","):
    # Argparse support to intake files, split values, etc
    tmp = []
    if not value:
        return tmp
    for v in value.split(delimiter):
        if path.exists(v) and v.endswith('.txt'):
            tmp.extend(file_read_lines(v))
        else:
            tmp.append(v)
    return unique_values(tmp)


################################
# Generic Utils Commonly Used
################################
def get_timestamp():
    return datetime.now().strftime('%m-%d-%Y %H:%M:%S')


def get_filestamp():
    # Timestamp formatted for filenames
    return datetime.now().strftime('%m-%d-%y_%H%M%S')


def gen_random_string(length=6):
    return ''.join(choice(ascii_letters + digits) for _ in range(length))


def percent_complete(item, item_list, decimal=1):
    # Take in item in array and calculate percentage complete for output formatting in programs.
    return "{1:.{0}%}".format(decimal, (item_list.index(item) / len(item_list)))


################################
# Regex Validations
################################
def ipv4check(data):
    # Check if string contains an IP address and return boolean value.
    ip_check = re.compile(r'''
            ^
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.  # First octet
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.  # Second octet
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.  # Third octet
            (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)    # Fourth octet
            $
        ''', re.VERBOSE)
    return bool(re.match(ip_check, data))


def internal_ipv4_check(data):
    # Must submit exact IP not string to check
    internal_ip_check = re.compile(r'''
            ^
            (127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|            # Loopback
            192\.168\.[0-9]{1,3}\.[0-9]{1,3}|                    # Private-Use Networks
            10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|              # Private-Use Networks
            172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}) # Private-Use Networks
            $
        ''', re.VERBOSE)
    return bool(re.match(internal_ip_check, data))


################################
# Encode/Decode Utils
#
# Turn into Bash Aliases:
# -------- --------- -----------
# alias decodeuri='python3 -c "from taser import utils; print(utils.decode_uri())"'
# alias encodeuri='python3 -c "from taser import utils; print(utils.encode_uri())"'
# alias encodeuricomp='python3 -c "from taser import utils; print(utils.encode_uri_component())"'
# alias b64encode='python3 -c "from taser import utils; print(utils.base64_encode())"'
# alias b64decode='python3 -c "from taser import utils; print(utils.base64_decode())"'
################################
def decode_uri(val=False):
    return unquote(val if val else sys.argv[1] if len(sys.argv) > 1 else '')


def encode_uri(val=False):
    # Replicates JavaScript's encodeURI
    val = val if val else sys.argv[1] if len(sys.argv) > 1 else ''
    return quote(val, safe='~()*!.\'-/')


def encode_uri_component(val=False):
    # Replicates JavaScript's encodeURIComponent
    val = val if val else sys.argv[1] if len(sys.argv) > 1 else ''
    return quote(val, safe='~()*!.\'-_')


def base64_encode(val=False):
    val = val if val else sys.argv[1] if len(sys.argv) > 1 else ''
    encoded_bytes = base64.b64encode(val.encode('utf-8'))
    return encoded_bytes.decode('utf-8')


def base64_decode(val=False):
    val = val if val else sys.argv[1] if len(sys.argv) > 1 else ''
    decoded_bytes = base64.b64decode(val.encode('utf-8'))
    return decoded_bytes.decode('utf-8')
