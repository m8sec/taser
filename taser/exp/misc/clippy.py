#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Clipboard monitor using only Python std libraries
#
# Usage:
# python3 clippy.py --cli -o output.txt
import argparse
import tkinter as tk
from time import sleep
from taser import BANNER
from datetime import datetime
from taser.logx import setup_file_logger, setup_cli_logger


class ClipboardMonitor:
    def __init__(self, args, cli_logger, file_logger):
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the main tkinter window
        self.last_clipboard = None
        self.args = args
        self.cli_logger = cli_logger
        self.file_logger = file_logger

    def get_clipboard_data(self):
        try:
            clipboard_data = self.root.clipboard_get()
            return clipboard_data
        except tk.TclError:
            return None  # No data on the clipboard

    def monitor_clipboard(self):
        while True:
            try:
                clipboard_data = self.get_clipboard_data()
                if clipboard_data != self.last_clipboard:
                    self.last_clipboard = clipboard_data
                    self.clipboard_changed(clipboard_data)
                sleep(1)  # Check every second
            except KeyboardInterrupt:
                raise SystemExit(0)

    def clipboard_changed(self, new_data):
        self.cli_logger.info(f"Clipboard changed: {new_data}") if self.args.cli else False
        self.file_logger.info(f'{datetime.now()} - {new_data}\n')


def build_parser():
    parser = argparse.ArgumentParser(description="\t\tclippy", formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('-o', dest='outfile', type=str, default=False, help='Output log file')
    parser.add_argument('--cli', dest='cli', action='store_true', help='Show changes in terminal')
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    cli_logger = setup_cli_logger(spacer=[4])
    cli_logger.info(BANNER)

    file_logger = setup_file_logger(args.outfile, mode='w')

    monitor = ClipboardMonitor(args, cli_logger, file_logger)
    monitor.monitor_clipboard()


if __name__ == "__main__":
    cli()
