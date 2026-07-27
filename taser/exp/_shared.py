import os
from threading import Lock

from taser import logx
from taser.http import extract_header, get_statuscode, get_title, web_request


WRITE_LOCK = Lock()


def proto_check(port, proto):
    return not ((port == 443 and proto == 'http') or (port == 80 and proto == 'https'))


def append_port(port, proto):
    if (int(port) == 80 and proto == 'http') or (int(port) == 443 and proto == 'https'):
        return ''
    return ':' + str(port)


def csv_field(value):
    return '"{}"'.format(str(value).replace('"', '""'))


def body_preview(text, limit=100):
    if not text:
        return ''
    normalized = ' '.join(str(text).split())
    return normalized[:limit]


def take_screenshot(url, args):
    if not getattr(args, 'screenshot', False):
        return ''

    os.makedirs(args.screenshot, exist_ok=True)
    from taser.http.browser import get_request

    resp = get_request(
        url,
        timeout=args.browser_timeout,
        load_time=args.load_time,
        proxies=args.proxy,
        browser=args.browser,
        driver_path=args.driver_path,
        screenshot=args.screenshot,
        headless=args.headless,
        window_size=args.window_size,
        language=args.language,
        page_load_strategy=args.page_load_strategy,
    )
    return getattr(resp, 'screenshot', '') if resp else ''


def log_http_result(resp, args, cli_logger, file_logger, screenshot='', preview=''):
    code = get_statuscode(resp)
    title = get_title(resp)
    server = extract_header('Server', resp)

    color_mapping = {200: 'green', 301: 'cyan', 302: 'cyan', 401: 'yellow', 403: 'yellow', 404: 'red', 500: 'red'}
    tmp_c = color_mapping.get(code, 'yellow')
    display_code = '{} => {}'.format(resp.history[0].status_code, code) if resp.history else code

    with WRITE_LOCK:
        cli_logger.write("{} {} {} {} {} {} {}".format(
            resp.url,
            logx.highlight('[{}]'.format(display_code), fg=tmp_c, style='none', windows=args.no_color),
            logx.highlight('[size: {}]'.format(len(resp.text)), fg='yellow', style='none', windows=args.no_color),
            logx.highlight('[{}]'.format(server), fg='cyan', style='none', windows=args.no_color),
            logx.highlight('[{}]'.format(title), fg='purple', style='none', windows=args.no_color),
            logx.highlight('[{}]'.format(screenshot), fg='green', style='none', windows=args.no_color) if screenshot else '',
            logx.highlight('[{}]'.format(preview), fg='gray', style='none', windows=args.no_color) if preview else '',
        ))

        row = [
            csv_field(resp.url),
            csv_field(code),
            csv_field(len(resp.text)),
            csv_field(title),
            csv_field(server),
            csv_field(resp.request.url),
            csv_field(screenshot),
        ]
        if hasattr(args, 'body_preview'):
            row.append(csv_field(preview))
        file_logger.info(','.join(row))


def do_http_probe(target, protocol, port, args, cli_logger, file_logger):
    url = f'{protocol}://{target}{append_port(port, protocol)}{args.page}'
    resp = web_request(url, timeout=args.timeout, proxies=args.proxy, redirects=not getattr(args, 'no_redirect', False))
    code = get_statuscode(resp)

    if code == 0:
        return False

    screenshot = take_screenshot(resp.url, args)
    preview = body_preview(resp.text, 100) if getattr(args, 'body_preview', False) else ''
    log_http_result(resp, args, cli_logger, file_logger, screenshot=screenshot, preview=preview)
    return True
