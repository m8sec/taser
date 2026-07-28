#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Recursively monitor a directory for new or modified files and directories.
# Optionally mirror discovered changes into a separate output location.
#
# Usage:
# python3 -m taser.exp.dir_monitor ./target
# python3 -m taser.exp.dir_monitor ./target --save
# python3 -m taser.exp.dir_monitor ./target --save ./mirror -o monitor.log

import argparse
import os
import shutil
import sys
from pathlib import Path
from threading import Lock
from time import sleep
from time import time_ns

from taser import BANNER
from taser.logx import setup_cli_logger, setup_debug_logger, setup_file_logger


WRITE_LOCK = Lock()


def csv_field(value):
    return '"{}"'.format(str(value).replace('"', '""'))


def detect_platform(platform_name):
    if platform_name != 'auto':
        return platform_name

    if sys.platform.startswith('win'):
        return 'windows'
    if sys.platform.startswith('linux'):
        return 'linux'
    if sys.platform == 'darwin':
        return 'macos'
    return 'linux'


def is_readable(path):
    try:
        if path.is_dir():
            with os.scandir(path) as entries:
                next(entries, None)
            return True

        if path.is_file():
            with open(path, 'rb'):
                return True

        return os.access(path, os.R_OK)
    except (OSError, PermissionError):
        return False


def is_writable(path, platform_name):
    try:
        if path.is_dir():
            probe_name = f'.taser_dir_monitor_write_test_{os.getpid()}_{time_ns()}'
            probe_path = path / probe_name
            file_descriptor = os.open(str(probe_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(file_descriptor)
            probe_path.unlink()
            return True

        if path.is_file():
            if platform_name == 'windows' and not os.access(path, os.W_OK):
                return False

            with open(path, 'ab'):
                return True

        return os.access(path, os.W_OK)
    except (OSError, PermissionError):
        return False


def get_permissions(path, platform_name):
    return {
        'readable': is_readable(path),
        'writable': is_writable(path, platform_name),
    }


def normalize_path(path):
    return Path(path).expanduser().resolve()


def is_relative_to(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def build_excluded_paths(target_root, args):
    excluded = set()

    if args.outfile:
        excluded.add(normalize_path(args.outfile))

    if args.save:
        save_root = normalize_path(args.save)
        mirror_root = save_root / target_root.name
        if is_relative_to(mirror_root, target_root):
            excluded.add(mirror_root)

    return excluded


def should_skip(path, excluded_paths):
    return any(path == excluded or is_relative_to(path, excluded) for excluded in excluded_paths)


def snapshot_directory(root_path, excluded_paths, platform_name):
    state = {}

    for current_root, dirnames, filenames in os.walk(root_path):
        current_path = normalize_path(current_root)

        if should_skip(current_path, excluded_paths):
            dirnames[:] = []
            continue

        dirnames[:] = [
            name for name in dirnames
            if not should_skip(current_path / name, excluded_paths)
        ]

        try:
            current_stat = current_path.stat()
            permissions = get_permissions(current_path, platform_name)
            state[str(current_path)] = {
                'kind': 'dir',
                'mtime_ns': current_stat.st_mtime_ns,
                'size': 0,
                'readable': permissions['readable'],
                'writable': permissions['writable'],
            }
        except OSError:
            pass

        for filename in filenames:
            file_path = current_path / filename
            if should_skip(file_path, excluded_paths):
                continue
            try:
                file_stat = file_path.stat()
                permissions = get_permissions(file_path, platform_name)
                state[str(file_path)] = {
                    'kind': 'file',
                    'mtime_ns': file_stat.st_mtime_ns,
                    'size': file_stat.st_size,
                    'readable': permissions['readable'],
                    'writable': permissions['writable'],
                }
            except OSError:
                continue

    return state


def emit_event(cli_logger, file_logger, event, path, metadata):
    readable_text = 'readable' if metadata['readable'] else 'not-readable'
    writable_text = 'writable' if metadata['writable'] else 'not-writable'
    kind = metadata['kind']
    size = metadata['size']

    with WRITE_LOCK:
        cli_logger.write(f'[{event}] [{kind}] [{readable_text}] [{writable_text}] {path} ({size} bytes)')
        file_logger.info(','.join([
            csv_field(event),
            csv_field(kind),
            csv_field(path),
            csv_field(readable_text),
            csv_field(writable_text),
            csv_field(size),
        ]))


def mirror_change(path, target_root, save_root, metadata, cli_logger):
    if not save_root:
        return

    source_path = normalize_path(path)
    destination_root = save_root / target_root.name
    relative_path = source_path.relative_to(target_root)
    destination_path = destination_root / relative_path

    try:
        if metadata['kind'] == 'dir':
            destination_path.mkdir(parents=True, exist_ok=True)
        else:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination_path)
    except OSError as exc:
        with WRITE_LOCK:
            cli_logger.warning(f'Failed to mirror {source_path} -> {destination_path}: {exc}', bullet='[!] ', fg='yellow')


def process_changes(previous_state, current_state, target_root, save_root, cli_logger, file_logger):
    for path in sorted(current_state.keys()):
        metadata = current_state[path]
        old_metadata = previous_state.get(path)

        if old_metadata is None:
            emit_event(cli_logger, file_logger, 'ADDED', path, metadata)
            mirror_change(path, target_root, save_root, metadata, cli_logger)
            continue

        if metadata['mtime_ns'] != old_metadata['mtime_ns'] or metadata['size'] != old_metadata['size']:
            emit_event(cli_logger, file_logger, 'MODIFIED', path, metadata)
            mirror_change(path, target_root, save_root, metadata, cli_logger)


def monitor_directory(args, cli_logger, file_logger):
    target_root = normalize_path(args.target)
    save_root = normalize_path(args.save) if args.save else None
    platform_name = detect_platform(args.platform)
    excluded_paths = build_excluded_paths(target_root, args)

    if not target_root.exists() or not target_root.is_dir():
        raise SystemExit(f'Invalid target directory: {target_root}')

    if save_root:
        (save_root / target_root.name).mkdir(parents=True, exist_ok=True)

    previous_state = snapshot_directory(target_root, excluded_paths, platform_name)

    with WRITE_LOCK:
        cli_logger.info(BANNER)
        cli_logger.info(f'Monitoring: {target_root}')
        cli_logger.info(f'Permission mode: {platform_name}')
        if save_root:
            cli_logger.info(f'Mirroring changes to: {save_root / target_root.name}')

    while True:
        sleep(args.interval)
        current_state = snapshot_directory(target_root, excluded_paths, platform_name)
        process_changes(previous_state, current_state, target_root, save_root, cli_logger, file_logger)
        previous_state = current_state


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{0}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument('target', help='Directory to monitor recursively')
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='Polling interval in seconds (default: 1.0)')
    parser.add_argument('--platform', choices=['auto', 'windows', 'linux', 'macos'], default='auto', help='Override the platform-specific permission probe mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    save_group = parser.add_argument_group("Save Options")
    save_group.add_argument('--save', nargs='?', const='.', default=False, help='Mirror changed files and directories to the given location (default: ./)')

    report = parser.add_argument_group("Output Options")
    report.add_argument('-o', '--outfile', action='store', help='CSV file to log results')

    parser.add_argument('--inject', help=argparse.SUPPRESS)
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    if args.inject:
        raise SystemExit('--inject is not supported')

    if args.debug:
        setup_debug_logger()

    cli_logger = setup_cli_logger(spacer=[4, 40])
    file_logger = setup_file_logger(args.outfile, mode='a' if args.outfile else 'w')
    file_logger.info('"Event","Type","Path","Readable","Writable","Size"')

    try:
        monitor_directory(args, cli_logger, file_logger)
    except KeyboardInterrupt:
        with WRITE_LOCK:
            cli_logger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
        raise SystemExit(0)


if __name__ == '__main__':
    cli()
