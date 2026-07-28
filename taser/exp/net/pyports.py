#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Python port scanner

import sys
import random
import logging
import argparse
import threading
from time import sleep
from ipparser import ipparser
from datetime import datetime

from taser import logx
from taser.utils import val2list, ranger

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

version = "0.1-beta"
top_1000_tcp = [2048, 1, 2049, 3, 4, 8192, 6, 7, 8193, 9, 8194, 8200, 6156, 13, 32773, 4111, 32775, 17, 2065, 19, 20,
                21, 22, 23, 24, 25, 26, 2068, 49175, 4125, 30, 4126, 32, 33, 4129, 8222, 37, 42, 43, 45100, 49, 2099,
                2100, 53, 2103, 2105, 2106, 2107, 12345, 8254, 2111, 70, 2119, 2121, 2126, 79, 80, 81, 82, 83, 84, 85,
                2135, 88, 89, 90, 61532, 2144, 8290, 99, 100, 8291, 8292, 14441, 106, 14442, 8300, 109, 110, 111, 2160,
                113, 2161, 119, 2170, 125, 4224, 2179, 135, 139, 8333, 2190, 143, 144, 2191, 146, 4242, 2196, 2200, 161,
                163, 2222, 27715, 179, 4279, 8383, 199, 6346, 2251, 8400, 8402, 211, 212, 2260, 222, 24800, 4321, 30951,
                2288, 6389, 4343, 49400, 8443, 2301, 254, 255, 256, 259, 55555, 264, 2323, 280, 51493, 301, 55600, 306,
                8500, 311, 2366, 31038, 10566, 2381, 2382, 2383, 10243, 340, 2393, 2394, 4443, 4444, 4445, 4446, 2399,
                20828, 2401, 4449, 6502, 366, 6510, 10616, 10617, 27000, 10621, 10626, 10628, 389, 10629, 6543, 6547,
                406, 407, 8600, 22939, 416, 417, 6565, 6566, 6567, 425, 427, 6580, 443, 444, 445, 2492, 2500, 57797,
                4550, 8649, 458, 8651, 8652, 61900, 8654, 464, 465, 4567, 2522, 2525, 481, 497, 500, 6646, 2557, 8701,
                512, 513, 514, 515, 55055, 55056, 6666, 6667, 524, 6668, 6669, 10778, 541, 543, 544, 545, 6689, 548,
                6692, 41511, 2601, 554, 555, 2602, 2604, 2605, 2607, 2608, 6699, 18988, 563, 4662, 33354, 587, 2638,
                593, 8800, 16992, 16993, 616, 617, 31337, 625, 60020, 631, 6779, 636, 62078, 6788, 6789, 646, 648, 6792,
                2701, 2702, 2710, 15000, 666, 667, 668, 2717, 2718, 15002, 15003, 15004, 19101, 2725, 8873, 683, 9091,
                35500, 687, 691, 6839, 8888, 700, 705, 8899, 711, 714, 720, 722, 726, 27352, 27353, 54328, 27355, 27356,
                58080, 6881, 749, 2800, 4848, 6901, 2809, 2811, 765, 777, 783, 787, 54045, 800, 801, 8994, 4899, 4900,
                808, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 2869, 6969, 2875, 843, 49999, 9040, 50000, 50001, 19283,
                50002, 50003, 21571, 50006, 7000, 7001, 7002, 9050, 7004, 2909, 2910, 7007, 11110, 11111, 2920, 873,
                7019, 9071, 880, 7025, 19315, 888, 9080, 9081, 898, 9090, 900, 901, 902, 903, 4998, 5000, 5001, 5002,
                5003, 5004, 9099, 911, 912, 5009, 9100, 9101, 9102, 9103, 9110, 2967, 2968, 9111, 19350, 7070, 5030,
                5033, 2998, 30718, 3000, 3001, 5050, 3003, 5051, 3005, 3006, 3007, 5054, 7100, 7103, 3011, 5060, 3013,
                5061, 7106, 18101, 3017, 23502, 48080, 981, 3030, 3031, 5080, 987, 990, 5087, 992, 993, 995, 999, 1000,
                1001, 1002, 60443, 3052, 5100, 5101, 1007, 5102, 1009, 1010, 1011, 9200, 9207, 1021, 1022, 1023, 1024,
                1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
                1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
                1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075,
                1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092,
                1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 5190, 1102, 9290, 1104, 1105, 1106, 1107, 1108, 5200,
                1110, 1111, 1112, 1113, 1114, 3071, 32770, 1117, 5214, 1119, 3168, 1121, 1122, 1123, 1124, 5221, 1126,
                5222, 5225, 1130, 1131, 1132, 5226, 33899, 64623, 1137, 1138, 32771, 1141, 1145, 3077, 1147, 1148, 1149,
                50300, 1151, 1152, 1154, 25734, 25735, 32772, 1163, 1164, 1165, 1166, 3211, 13456, 1169, 44176, 10002,
                3221, 1174, 1175, 5269, 10004, 1183, 5280, 1185, 1186, 1187, 5120, 1192, 64680, 1198, 1199, 1201, 5298,
                3260, 1213, 3261, 32774, 1216, 1217, 1218, 32768, 3268, 3269, 9415, 9418, 1233, 1234, 3283, 1236, 50389,
                1244, 1247, 1248, 3300, 3301, 3306, 1259, 7402, 5357, 32776, 1271, 1272, 3322, 3323, 3324, 1277, 3325,
                40193, 3333, 1287, 32777, 7435, 9485, 1296, 7443, 1300, 1301, 3351, 9500, 1309, 1310, 1311, 5405, 9502,
                9503, 32778, 65389, 5414, 3367, 3369, 1322, 3370, 3371, 3372, 15660, 1328, 30000, 9220, 1334, 5431,
                5432, 32779, 3389, 3390, 9535, 5440, 32769, 19780, 50500, 1352, 7496, 3404, 32780, 7512, 19801, 8007,
                9575, 32781, 8010, 9593, 3128, 9594, 5500, 9595, 15742, 7200, 19842, 32782, 5510, 7201, 1417, 9618,
                3476, 38292, 1433, 1434, 13722, 44442, 32783, 44443, 56737, 56738, 1443, 3493, 5544, 5550, 1455, 5555,
                1461, 32784, 5560, 3517, 5566, 52673, 9666, 40911, 3527, 7625, 7627, 50636, 32785, 17877, 1494, 13782,
                13783, 44501, 3546, 1500, 1501, 1503, 3551, 65000, 51103, 1521, 1524, 3580, 1533, 7676, 5631, 5633,
                49152, 57294, 49153, 49154, 42510, 49155, 1556, 49156, 49157, 49158, 20000, 5666, 49159, 20005, 28201,
                49160, 1580, 5678, 1583, 5679, 49161, 49163, 1594, 7741, 20031, 1600, 49165, 17988, 3659, 49167, 5718,
                52822, 7777, 5730, 7778, 26214, 1641, 3689, 3690, 65129, 50800, 52848, 3703, 7800, 18040, 1658, 49176,
                16000, 16001, 1666, 52869, 16012, 16016, 16018, 9876, 9877, 9878, 1687, 1688, 3737, 1700, 5800, 5801,
                5802, 9898, 9900, 14000, 5810, 5811, 1717, 1718, 1719, 1720, 1721, 3766, 1723, 5815, 9917, 5822, 11967,
                5825, 3784, 9929, 16080, 9943, 3800, 3801, 5850, 1755, 9944, 12000, 1761, 3809, 5859, 3814, 5862, 7911,
                7920, 7921, 3826, 3827, 3828, 5877, 1782, 1783, 9968, 16113, 20221, 20222, 7937, 7938, 1801, 3851, 5900,
                1805, 5901, 5902, 5903, 5904, 5906, 5907, 1812, 9998, 5910, 5911, 9999, 10000, 10001, 5915, 10003, 3869,
                10009, 3871, 10010, 10012, 5922, 5925, 3878, 3880, 10024, 10025, 14238, 1839, 1840, 3889, 5950, 7999,
                5952, 3905, 8000, 8001, 8002, 1862, 1863, 1864, 5959, 3914, 5960, 5961, 5962, 3918, 5963, 3920, 8008,
                8009, 1875, 8011, 8021, 8022, 8031, 10082, 5987, 5988, 5989, 63331, 3945, 8042, 1900, 8045, 5998, 5999,
                6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 34571, 6009, 1914, 34572, 24444, 34573, 3971, 6025,
                12174, 1935, 8080, 8081, 3986, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 1947, 3995, 8090, 3998,
                8093, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 8099, 8100, 6059, 1971, 1972, 1974, 1984, 10180, 4045,
                1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 6100, 6101, 2013, 6106,
                6112, 2020, 2021, 2022, 10215, 12265, 6123, 2030, 2033, 2034, 2035, 6129, 8180, 2038, 8181, 2040, 2041,
                2042, 2043, 2045, 2046, 2047]


########################
# Port Scan methods
########################
class NetScan:
    @staticmethod
    def syn_scan(target, port, timeout=2, source_port=False):
        sport = source_port if source_port else RandShort()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="S"), timeout=timeout, verbose=0)
        if pkt is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:
                    return "Closed"
                elif pkt[TCP].flags == 0x12:
                    return "Open"
                else:
                    return f"Filtered (TCP Response: {pkt[TCP].flags})"
            elif pkt.haslayer(ICMP):
                return "Filtered (ICMP Response)"
            else:
                return "Closed (Unknown)"
        else:
            return "Closed (Unanswered)"

    @staticmethod
    def tcp_scan(target, port, timeout=2, source_port=False):
        sport = source_port if source_port else RandShort()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="S"), timeout=timeout, verbose=0)

        if pkt is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x12:  # TCP SYN-ACK
                    # Send a RST to close the connection
                    send(IP(dst=target) / TCP(sport=sport, dport=port, flags="RA"), verbose=0)
                    return "Open"
                elif pkt[TCP].flags == 0x14:  # TCP RST-ACK
                    return "Closed"
                else:
                    return f"Filtered (TCP Response: {pkt[TCP].flags})"
            elif pkt.haslayer(ICMP):
                return "Filtered (ICMP Response)"
            else:
                return "Closed (Unknown)"
        else:
            return "Closed (Unanswered)"

    @staticmethod
    def fin_scan(target, port, timeout=2, source_port=False):
        sport = source_port if source_port else RandShort()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="F"), timeout=timeout, verbose=0)

        if pkt is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:  # TCP RST-ACK
                    return "Closed"
                else:
                    return f"Filtered (TCP Response: {pkt[TCP].flags})"
            elif pkt.haslayer(ICMP):
                return "Filtered (ICMP Response)"
            else:
                return "Closed (Unknown)"
        else:
            return "Open or Filtered"

    @staticmethod
    def xmas_scan(target, port, timeout=2, source_port=False):
        sport = source_port if source_port else RandShort()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="FPU"), timeout=timeout, verbose=0)

        if pkt is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:  # TCP RST-ACK
                    return "Closed"
                else:
                    return f"Filtered (TCP Response: {pkt[TCP].flags})"
            elif pkt.haslayer(ICMP):
                return "Filtered (ICMP Response)"
            else:
                return "Closed (Unknown)"
        else:
            return "Filtered (No Response)"

    def ack_scan(target, port, timeout=2, source_port=False):
        sport = source_port if source_port else RandShort()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="A"), timeout=timeout, verbose=0)

        if pkt is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:  # TCP RST-ACK
                    return "Unfiltered"
                else:
                    return f"Filtered (TCP Response: {pkt[TCP].sprintf('%TCP.flags%')})"
            elif pkt.haslayer(ICMP):
                return "Filtered (ICMP Response)"
            else:
                return "Filtered (Unknown)"
        else:
            return "Filtered (No Response)"

    @staticmethod
    def udp_scan(target, port, timeout=2, source_port=False):
        sport = source_port if source_port else RandShort()
        pkt = sr1(IP(dst=target) / UDP(sport=sport, dport=port), timeout=timeout, verbose=0)

        if pkt is not None:
            if pkt.haslayer(UDP):
                return "Open"
            elif pkt.haslayer(ICMP):
                if pkt[ICMP].type == 3 and pkt[ICMP].code == 3:
                    return "Closed (ICMP Response)"
                elif pkt[ICMP].type == 3 and pkt[ICMP].code in [1, 2, 9, 10, 13]:
                    return "Filtered (ICMP Response)"
                else:
                    return f"Filtered (Unknown ICMP Response: {pkt[ICMP].type}/{pkt[ICMP].code})"
            else:
                return f"Filtered (Unknown Response: {pkt.summary()})"
        else:
            return "Filtered (No Response)"

    @staticmethod
    def ping_scan(target, timeout=2):
        # ICMP Echo Reqeust
        pkt = sr1(IP(dst=target) / ICMP(), timeout=timeout, verbose=0)

        if pkt is not None:
            if pkt.haslayer(ICMP):
                if pkt[ICMP].type == 0 and pkt[ICMP].code == 0:
                    return "Active"
                else:
                    return f"Inactive (Unknown ICMP Response: {pkt[ICMP].type}/{pkt[ICMP].code})"
            else:
                return f"Inactive (Unknown response: {pkt.summary()})"
        else:
            return "Inactive (No Response)"


########################
# Scan Logic
########################
class PyScan:
    def __init__(self, args):
        self.cli = False
        self.log = False
        self.csv = False
        self.ipp = False

        self.active = []
        self.args = args
        self.ports = define_ports(args)
        self.hosts = ipparser(args.target[0] if args.target[0] != "pipe" else False)

        self.setup_loggers()
        self.init_reports()

    def setup_loggers(self):
        self.cli = logx.setup_cli_logger(logger_name='cli', auto_adapter=False)
        self.log = logx.setup_file_logger(self.args.default_report, logger_name='log')
        self.ipp = logx.setup_file_logger(self.args.ipp_report, logger_name='ipp')
        self.csv = logx.setup_file_logger(self.args.csv_report, logger_name='csv')

    def init_reports(self):
        self.log.info("{}\nStarting Scan:".format(' '.join(sys.argv))) if not self.args.data_only else False
        self.csv.info('"Host","Port","Status",')

    def start(self):
        # Discovery Scan
        if self.args.no_ping or self.args.ping_scan:
            logging.debug('Skipping discovery scan')
            self.active = self.hosts
        else:
            try:
                for host in self.hosts if self.args.disable_random else random.sample(self.hosts, len(self.hosts)):
                    threading.Thread(target=self.discovery_handler, args=(host,), daemon=True).start()
                    while threading.active_count() > self.args.max_threads:
                        sleep(0.05)
                while threading.active_count() > 1:
                    sleep(0.05)
            except KeyboardInterrupt:
                logx.color('Key event detected, closing...', fg='yellow', windows=self.args.no_color)
                sys.exit(0)

        # Port Scan
        for host in self.active if self.args.disable_random else random.sample(self.active, len(self.active)):
            for port in random.sample(self.ports, len(self.ports)):
                try:
                    threading.Thread(target=self.scan_handler, args=(host, port), daemon=True).start()
                    while threading.active_count() > self.args.max_threads:
                        sleep(0.05)
                except KeyboardInterrupt:
                    logx.color('Key event detected, closing...', fg='yellow', windows=self.args.no_color)
                    sys.exit(0)

        # Ensure complete before return
        while threading.active_count() > 1:
            sleep(0.05)

    def discovery_handler(self, host):
        status = 'Inactive (Default)'

        if self.args.echo_ping:
            status = NetScan.ping_scan(host, self.args.timeout)
            if status.startswith('Active'):
                self.active.append(host)
                return self.print_discovery_status(host, "Active (ICMP)")
        else:
            ping = {'syn_ping': NetScan.syn_scan, 'ack_ping': NetScan.ack_scan}

            for k, v in vars(self.args).items():
                if k.endswith('_ping') and v:
                    for p in self.args.discovery_port:
                        status = ping[k](host, int(p), self.args.timeout, self.args.source_port)
                        if status.startswith(('Open', 'Unfiltered')):
                            self.active.append(host)
                            return self.print_discovery_status(host, f"Active ({k} - {p})")

        return self.print_discovery_status(host, status)

    def scan_handler(self, host, port):
        if self.args.ping_scan:
            logging.debug(f'Executing ping_scan for {host}')
            status = NetScan.ping_scan(host, self.args.timeout)
            return self.print_discovery_status(host, status)

        for k, v in vars(self.args).items():
            if k.endswith('_scan') and v:
                logging.debug(f'Executing {k} for {host}:{port}')
                status = getattr(NetScan, k)(host, port, self.args.timeout, self.args.source_port)
                return self.print_scan_status(host, port, status)

    def print_status(self, data):
        if self.args.verbose or not self.args.data_only:
            self.cli.info('{}'.format(data))
            self.log.info('{}'.format(data))

    def print_discovery_status(self, host, status):
        if status.startswith("Active") or self.args.verbose:
            self.cli.info('{} {}'.format(host, status))
            self.log.info('{} {}'.format(host, status))
            self.csv.info('"{}","","{}",'.format(host, status))

    def print_scan_status(self, host, port, status):
        if status.startswith("Open") or self.args.verbose:
            self.cli.info('{}:{} {}'.format(host, port, '' if self.args.data_only else status))
            self.log.info('{}:{} {}'.format(host, port, status))
            self.csv.info('"{}","{}","{}",'.format(host, port, status))
            self.ipp.info(f'{host}:{port}')

        elif status.startswith('Filter') and not self.args.data_only:
            self.cli.info('{}:{} {}'.format(host, port, status))


########################
# Scan Helper Func
########################
def define_ports(args):
    # get ports based on cmd args
    if args.ping_scan:
        return [0]
    if args.port in ['all', '-']:
        return ranger('1-65535')
    elif args.port:
        return ranger(args.port)
    else:
        return top_1000_tcp


########################
# Debug Func
########################
def setup_debug_logger(args):
    debug_output_string = "{} %(message)s".format(logx.highlight('DEBUG', 'purple', windows=args.no_color))
    formatter = logging.Formatter(debug_output_string)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.propagate = False
    root_logger.addHandler(streamHandler)
    root_logger.setLevel(logging.DEBUG)
    return root_logger


def debug_args(args):
    for k, v in vars(args).items():
        logging.debug(f'{k} -> {v}')


########################
# CMD Args
########################
def build_parser():
    parser = argparse.ArgumentParser("Port Scanner")
    config = parser.add_argument_group("Config Options")
    config.add_argument("--debug", action='store_true', help="Enable Debug Mode")
    config.add_argument("-v", "--verbose", action='store_true', help="Show closed ports")
    config.add_argument('-T', dest='max_threads', type=int, default=85, help='Max threads (Default: 85)')
    config.add_argument('-t', dest='timeout', type=float, default=3, help='Connection timeout')

    ev = parser.add_argument_group("Evasion Options")
    ev.add_argument('-g', '--source-port', type=int, default=False, help='Define source port (random*)')
    ev.add_argument("--disable-random", action='store_true', help="Disable host randomization")

    disc = parser.add_argument_group("Asset Discovery Options")
    disc_type = disc.add_mutually_exclusive_group(required=False)
    disc_type.add_argument("-Pn", dest='no_ping', action='store_true', help="All hosts active (No ping sweep)")
    disc_type.add_argument("-PE", dest='echo_ping', action='store_true', help="IMPC ECHO ping (Default*)")
    disc_type.add_argument("-PS", dest='syn_ping', action='store_true', help="use SYN ping")
    disc_type.add_argument("-PA", dest='ack_ping', action='store_true', help="Use ACK Ping")
    disc.add_argument("-dp", dest='discovery_port', default='22,80,139,110,443', type=lambda x: val2list(x), help="Comma sep. discovery ports (22,110,139,80,443*)")

    scan = parser.add_argument_group("Scan Options")
    scan_type = scan.add_mutually_exclusive_group(required=False)
    scan_type.add_argument("-sT", dest='tcp_scan', action='store_true', help="TCP Scan")
    scan_type.add_argument("-sS", dest='syn_scan', action='store_true', help="Syn Scan (Default)")
    scan_type.add_argument("-sF", dest='fin_scan', action='store_true', help="Fin Scan")
    scan_type.add_argument("-sX", dest='xmas_scan', action='store_true', help="Xmas Scan")
    scan_type.add_argument("-sA", dest='ack_scan', action='store_true', help="Ack Scan")
    scan_type.add_argument("-sU", dest='udp_scan', action='store_true', help="UDP Scan")
    scan_type.add_argument("-sn", dest='ping_scan', action='store_true', help="Ping sweep (no ports)")

    out = parser.add_argument_group("Reporting Options")
    out.add_argument('--no-color', action='store_true', help="No color output")
    out.add_argument('--data-only', action='store_true', help="Open IP:Port only in CLI")
    out.add_argument('-oN', dest='default_report', type=str, default=False, help='Default Report')
    out.add_argument('-oP', dest='ipp_report', type=str, default=False, help='IP:Port Report')
    out.add_argument('-oC', dest='csv_report', type=str, default=False, help='CSV Report')

    target = parser.add_argument_group("Target Options")
    target.add_argument("-p", "--port", type=str, default=False, help="Port, range, or \"all\"")
    target.add_argument(dest='target', nargs='+', help='Target: Domain, comma separated list, txt files, range')
    return parser


def cli(argv=None):
    return build_parser().parse_args(argv)


def set_defaults(args):
    # Validate methods & enforce defaults
    if not any(getattr(args, k, False) for k in dir(args) if k.endswith('_scan')):
        args.syn_scan = True

    if not any(getattr(args, k, False) for k in dir(args) if k.endswith('_ping')):
        args.echo_ping = True


########################
# Entry Point & Main
########################
def main():
    args = cli()
    set_defaults(args)

    setup_debug_logger(args) if args.debug else False
    debug_args(args) if args.debug else False

    try:
        p = PyScan(args)
        start_timer = datetime.now()

        p.print_status("Starting {} {} at {}\n".format(sys.argv[0], version, start_timer.strftime('%m-%d-%Y %H:%M:%S')))
        p.start()

        p.print_status(f"\nScan complete. {len(p.hosts)} hosts ({len(p.active)} active) in ({datetime.now()-start_timer})")
    except KeyboardInterrupt:
        logx.color('Key event detected, closing...', fg='yellow', windows=args.no_color)
        sys.exit(0)


if __name__ == '__main__':
    main()
