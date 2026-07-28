#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Send SMTP messages with Taser
#
# Requirements
# pip3 install taser
#
# Usage:
# python3 smtp_relay.py -t test@test.com -f admin@test.com -s 127.0.0.1 -p 587 -s test_msg -b body.txt
import argparse
from os import path
from sys import argv
from taser import BANNER
from taser.utils import val2list
from taser.smtp import smtp_relay

def build_parser():
    parser = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]),formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)

    parser.add_argument('-r', dest='relay_srv', type=str, required=True, help='Address of relay server')
    parser.add_argument('-p', dest='relay_port', type=int, default=25, help='Address of relay server')

    parser.add_argument('-t', dest='to_addr', type=lambda x: val2list(x), default=[], required=True, help='Sent Address')
    parser.add_argument('-f', dest='from_addr', type=lambda x: val2list(x), default=[], required=True, help='Sent From')

    parser.add_argument('-s', dest='subject', type=str, required=True, help='Email Subject')
    parser.add_argument('-b', dest='body', type=str, required=True, help='Email Body')

    parser.add_argument('--password', dest='auth_pwd', type=str, default=False, help='Auth password')
    parser.add_argument('-A', dest='attachment', type=str, default=False, help='Message Attachment')
    parser.add_argument('--tls', dest='tls', action='store_true', help='Start TLS option')
    parser.add_argument('--reply-to', dest='reply_to', type=str, default=False, help='Set different reply to address')
    parser.add_argument('-T', '--type', dest='msg_type', choices=['txt', 'html'], default='html', help='Message Type')
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    print(BANNER)
    print('[*] Starting SMTP Relay PoC')

    if path.exists(args.body):
        try:
            body_path = args.body
            with open(body_path, "r", encoding='utf-8') as handle:
                args.body = handle.read()
            print('[+] Message body added from: {}'.format(body_path))
        except Exception as e:
            print('[!] Failed to read file: {}'.format(str(e)))
            exit(1)

    print('[*] Using server: {}:{}'.format(args.relay_srv, args.relay_port))
    print('[*] Sending to {} recipients'.format(len(args.to_addr)))
    for sender in args.from_addr:
        for user in args.to_addr:
            try:
                sent = smtp_relay(sender, user, args.subject, args.body, args.relay_srv, args.relay_port, args.auth_pwd,
                                  attachment=args.attachment, msg_type=args.msg_type, reply_to=args.reply_to, tls=args.tls)
                print('[+] Success: {}'.format(user)) if sent else print('[-] Failed: {}'.format(user))
            except Exception as e:
                print('[-] Failed: {} -{}'.format(user, e))
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                exit(0)


if __name__ == '__main__':
    cli()
