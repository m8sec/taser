#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Reverse SOCKS5 server with a local SOCKS listener and a separate reverse-client
# listener for sprox clients.
#
# Info:
# Point local SOCKS-aware tools at --bind-host/--bind-port and have sprox clients
# connect back to --client-host/--client-port.
#
# Usage:
# python3 -m taser.exp.prox.sprox_server --bind-host 127.0.0.1 --bind-port 8080 --client-host 0.0.0.0 --client-port 8081

from __future__ import annotations

import argparse
import sys
from typing import Optional

from taser import BANNER
from taser.logx import setup_cli_logger
from taser.prox import ReverseSocksServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--bind-host", default="127.0.0.1", help="SOCKS5 listener host")
    parser.add_argument("--bind-port", type=int, default=8080, help="SOCKS5 listener port")
    parser.add_argument("--client-host", default="127.0.0.1", help="Reverse client listener host")
    parser.add_argument("--client-port", type=int, default=8081, help="Reverse client listener port")
    return parser


def cli(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    cli_logger = setup_cli_logger(spacer=[4, 30])
    cli_logger.info(BANNER)

    try:
        server = ReverseSocksServer(
            bind_host=args.bind_host,
            bind_port=args.bind_port,
            client_host=args.client_host,
            client_port=args.client_port,
            logger=lambda message: cli_logger.write(message),
        )
    except OSError as exc:
        cli_logger.warning("Failed to start server: {}".format(exc), bullet='[!] ', fg='yellow')
        raise SystemExit(1)

    cli_logger.info("SOCKS5 listener: {}:{}".format(*server.bind_address))
    cli_logger.info("Client listener: {}:{}".format(*server.client_address))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        cli_logger.warning("Key event detected, closing...", bullet='[!] ', fg='yellow')
        server.shutdown()
        raise SystemExit(0)


if __name__ == "__main__":
    cli()
