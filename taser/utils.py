import re
import threading
from os import path
from time import sleep
from random import choice
from string import ascii_letters, digits
from datetime import datetime, timedelta


class Timeout(threading.Thread):
    # Simple class to self-manage execution timeouts.

    def __init__(self, timeout):
        threading.Thread.__init__(self)
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


def read_file_lines(file):
    return [line.strip() for line in open(file)]


def file_exists(parser, filename, contents=True):
    # Argparse support for accepting & validating files
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    if contents:
        return read_file_lines(filename)
    else:
        return filename


def delimiter2list(value, delim=","):
    return value.split(delim) if value else []


def delimiter2dict(value, delim_one=";", delim_two=":"):
    x = {}
    for item in value.split(delim_one):
        if item:
            sp = item.split(delim_two)
            x[sp[0].strip()] = delim_two.join(sp[1:]).strip()
    return x


def ranger(size_input):
    # Takes comma separated or range of number inputs and
    # returns a single list to iterate over.
    t = []
    for x in delimiter2list(size_input):
        if "-" in x:
            t += [y for y in range(int(x.split('-')[0]), int(x.split('-')[1])+1)]
        else:
            t.append(int(x))
    return t


def get_timestamp():
    return datetime.now().strftime('%m-%d-%Y %H:%M:%S')


def get_filestamp():
    # Timestamp formatted for filenames
    return datetime.now().strftime('%m-%d-%y-%H%M%S')


def gen_random_string(length=6):
    return''.join([choice(ascii_letters + digits) for x in range(length)])


def percent_complete(item, item_list, decimal=1):
    # Take in item in array and calculate percentage complete for output formatting in programs.
    return "{1:.{0}%}".format(decimal, (item_list.index(item) / len(item_list)))


def ipcheck(data):
    # Check if string contains an IP address and return boolean value.
    ip_check = '''(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
    if re.search(ip_check, data):
        return True
    return False


def internal_ipcheck(data):
    # Must submit exact IP not string to check
    ip_check = '''(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.1[6-9]\.[0-9]{1,3}\.[0-9]{1,3}|172\.2[0-9]\.[0-9]{1,3}\.[0-9]{1,3}|172\.3[0-1]\.[0-9]{1,3}\.[0-9]{1,3})'''
    check = re.findall(ip_check, data)
    return check if check else False

