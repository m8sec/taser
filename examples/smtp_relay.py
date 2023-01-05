#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Send SMTP messages with Taser
#
# Usage:
# python3 smtp_relay.py -t test@test.com -f admin@test.com -s 127.0.0.1 -p 587 -s test_msg -b body.txt
import argparse
from sys import argv
from taser.version import BANNER
from taser.utils import file_exists
from taser.smtp import smtp_relay

if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]),formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)

    args.add_argument('-r', dest='relay_srv', type=str, required=True, help='Address of relay server')
    args.add_argument('-p', dest='relay_port', type=int, default=25, help='Address of relay server')

    users = args.add_mutually_exclusive_group(required=True)
    users.add_argument('-t', dest='to_addr', action='append', default=[], help='Sent Address')
    users.add_argument('-T', dest='to_addr', type=lambda x: file_exists(x), help='File of Addresse')

    args.add_argument('-f', dest='from_addr', type=str, required=True, help='Sent From')
    args.add_argument('-s', dest='subject', type=str, required=True, help='Email Subject')
    args.add_argument('-b', dest='body', type=str, required=True, help='Email Body')

    args.add_argument('--password', dest='auth_pwd', type=str, default=False, help='Auth password')
    args.add_argument('-A', dest='attachment', type=str, default=False, help='Message Attachment')
    args.add_argument('--tls', dest='tls', action='store_true', help='Start TLS option')
    args.add_argument('--reply-to', dest='reply_to', type=str, default=False, help='Set different reply to address')
    args.add_argument('--type', dest='msg_type', choices=['txt', 'html'], default='html', help='Message Type')
    args = args.parse_args()

    print(BANNER)
    print('[*] Starting SMTP Relay PoC')

    if args.body.endswith('txt'):
        try:
            b = open(args.body, "r")
            body = b.read()
            b.close()
            print('[+] Message body added from: {}'.format(args.body))
        except Exception as e:
            print('[!] Failed to read file: {}'.format(str(e)))
            exit(1)

    print('[*] Using server: {}:{}'.format(args.relay_srv, args.relay_port))
    print('[*] Sending to {} recipients'.format(len(args.to_addr)))
    for user in args.to_addr:
        try:
            smtp_relay(args.from_addr, user, args.subject, args.body, args.relay_srv, args.relay_port, args.auth_pwd,
                       attachment=args.attachment, msg_type=args.msg_type, reply_to=args.reply_to, tls=args.tls)
            print('[+] Success: {}'.format(user))
        except Exception as e:
            print('[-] Failed: {} -{}'.format(user, e))
        except KeyboardInterrupt:
            print("\n[!] Key Event Detected...\n\n")
            exit(0)
