#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Enumerate SSL Certs and versions useful for
# SSL vulns based on version and recon
#
# Usage:
# python3 ssl_enum.py <target>
import sys
import ssl
import socket
import argparse
from time import sleep
from OpenSSL import crypto
from datetime import datetime
from ipparser import ipparser
from taser.logx import highlight, color
from threading import Thread, active_count

def ssl_getDefaultContext(host, port, timeout=4):
    '''
    Extract server's default SSL/TLS version
    '''
    version = False
    s = None
    ss = None
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ss = ctx.wrap_socket(s, server_hostname=host)
        version = ss.version()
    except Exception:
        return version
    finally:
        if ss:
            ss.close()
        if s:
            s.close()
    return version


def ssl_versionConnect(host, port, version, timeout):
    '''
    Generic SSL/TLS connection function
    '''
    opt = {
        #'SSLv2'   : ssl.OP_NO_SSLv2,    # Depreciated since openssl v3.6
        #'SSLv3'   : ssl.OP_NO_SSLv3,    # Depreciated since openssl v3.6
        'TLSv1.0' : ssl.OP_NO_TLSv1,
        'TLSv1.1' : ssl.OP_NO_TLSv1_1,
        'TLSv1.2' : ssl.OP_NO_TLSv1_2,
        'TLSv1.3' : ssl.OP_NO_TLSv1_3
    }

    socket.setdefaulttimeout(timeout)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options = ssl.OP_ALL| ssl.OP_CIPHER_SERVER_PREFERENCE|ssl.OP_ENABLE_MIDDLEBOX_COMPAT|ssl.OP_NO_COMPRESSION

    for x in opt.keys():
            ctx.options |= opt[x] if x != version else False

    ss = ctx.wrap_socket(s, server_hostname=host, do_handshake_on_connect=True)
    ss.close()
    s.close()
    return True


def ssl_versionCheck(host, port, timeout=4, verbose=False):
    '''
    Function to check compatible SSL/TLS versions
    '''
    default = ssl_getDefaultContext(host, port, timeout)
    ssl_ver = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

    for v in ssl_ver:
        try:
            a = "{:<4}{:<12}{}".format(' ', v, 'True (Preferred)' if v == default else ssl_versionConnect(host, port, v, timeout))
            if v in ["SSLv2", "SSLv3", "TLSv1.0"]:
                a = highlight(a, fg='red')
            print(a)
        except Exception as e:
            if verbose:
                print('{:<4}{:<12}{}'.format(' ', v, 'False (NOT AVAILABLE)' if " NO_PROTOCOLS_AVAILABLE" in str(e) else "False"))
    if default and default not in ssl_ver:
        print("{:<4}{:<12}True (Preferred)".format(' ', default))


def get_sslCert(host, port:int, timeout=4):
    data = {}
    s = None
    ss = None
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=host, do_handshake_on_connect=True)

        cert = ss.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

        data['ip'] = ss.getpeername()[0]
        data['issuer'] = x509.get_issuer().CN
        data['subject'] = x509.get_subject().CN
        data['not_after'] = datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
        data['not_before'] = datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
        data['self_signed'] = True if data['issuer'] == data['subject'] else False
        data['expired'] = True if data['not_after'] < datetime.now() else False

    except Exception:
        return data
    finally:
        if ss:
            ss.close()
        if s:
            s.close()
    return data


def thread_launcher(args, target):
        host,port = target.split(':') if ':' in target else [target, args.port]
        try:
            c = get_sslCert(host, int(port), timeout=args.timeout)
            if not c:
                color('[-] {}:{:<5} Failed to retrieve certificate'.format(host, port), fg='red')
                return
            color('[*] {}:{:<5} ({})'.format(host, port, c['ip']))
            color('{:<4}{:<12}{}'.format(' ', 'Subject',    c['subject']), fg='red' if c['self_signed'] else 'green')
            color('{:<4}{:<12}{}'.format(' ', 'Issuer',     c['issuer']), fg='red' if c['self_signed'] else 'green')
            color('{:<4}{:<12}{}'.format(' ', 'Expires', c['not_after'].strftime('%Y-%m-%d')), fg='red' if c['expired'] else 'green')
            ssl_versionCheck(host, int(port), timeout=args.timeout) if args.version else False
        except KeyboardInterrupt:
            sys.exit(0)


def main(args, targets):
    print('[+] Starting SSL Enumeration against: [{} host(s)]'.format(len(targets)))
    for t in targets:
        Thread(target=thread_launcher, args=(args, t), daemon=True).start()
        while active_count() >= args.max_threads:
            sleep(0.05)
    while active_count() > 1:
        sleep(0.05)


def build_parser():
    parser = argparse.ArgumentParser(description='\t\tSSL Enumeration', formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('-T', dest='max_threads', type=int, default=10, help='Max threads')
    parser.add_argument('-t', dest='timeout', type=int, default=4, help='Request timeout')
    parser.add_argument('-p', '--port', dest='port', type=int, default=443, help='Target Port')
    parser.add_argument('--version', dest='version', action='store_true', help='Enumerate SSL Versions enabled')
    parser.add_argument(dest='target', nargs='+', help='Target Host/DNS Name')
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    targets = ipparser(args.target[0], resolve=False, open_ports=True, exit_on_error=False)
    main(args, targets)


if __name__ == '__main__':
    cli()
