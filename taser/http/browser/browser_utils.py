from hashlib import sha1
from os import path
from taser.http import URLParser
from types import SimpleNamespace
from taser.utils import file_collision_check


def build_requests_object(driver, elapsed_time=False, screenshot=False):
    # Post request, use the driver object to build requests like response
    fname = False
    url = driver.current_url

    if screenshot:
        # Save screenshot with domain as name
        parsed = URLParser.read_structured(url)
        host = URLParser.extract_subdomain(url)
        port = parsed.port if getattr(parsed, 'port', '') else (443 if parsed.proto == 'https' else 80)
        page_hash = sha1((parsed.path or '/').encode('utf-8')).hexdigest()[:8]
        screenshot_name = f"{parsed.proto}_{host}_{port}_{page_hash}.png"
        fname = file_collision_check(path.join(screenshot, screenshot_name), ext='png')
        driver.save_screenshot(fname)

    return SimpleNamespace(
        # Build requests response object
        driver=driver,
        url=url,
        screenshot=fname,
        elapsed=elapsed_time,
        title=driver.title if driver else '',
        text=driver.page_source if driver else '',
        cookies=driver.get_cookies() if driver else {},
        content=driver.page_source.encode('utf-8') if driver else ''
    )
