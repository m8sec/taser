#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Serve a local directory over HTTP with optional file uploads and downloads.
#
# Usage:
# python3 -m taser.exp.fileshare
# python3 -m taser.exp.fileshare --dir ./share --host 127.0.0.1 --port 8080

import argparse
import sys
from pathlib import Path

from taser import BANNER
from taser.http.fileshare import LocalFileShareServer
from taser.logx import setup_cli_logger


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--dir", default=".", help="Directory to serve (default: current directory)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8080, help="Bind port")
    parser.add_argument("--read-only", action="store_true", help="Disable file uploads")
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)
    cli_logger = setup_cli_logger(spacer=[4, 32])
    cli_logger.info(BANNER)

    base_dir = Path(args.dir).expanduser().resolve()
    server = LocalFileShareServer(
        base_dir=base_dir,
        host=args.host,
        port=args.port,
        allow_upload=not args.read_only,
        logger=lambda message: cli_logger.write(message),
    )

    cli_logger.info(f"Serving: {base_dir}")
    cli_logger.info(f"Listening on http://{args.host}:{args.port}")
    cli_logger.info("Uploads: enabled" if not args.read_only else "Uploads: disabled")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        cli_logger.warning("Key event detected, closing...", bullet='[!] ', fg='yellow')
        server.shutdown()
        raise SystemExit(0)


if __name__ == "__main__":
    cli()
