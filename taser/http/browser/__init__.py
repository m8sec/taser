from taser import LOG
from taser.http.browser.chrome import ChromeBrowser
from taser.http.browser.firefox import FirefoxBrowser


def get_request(url, headers=None, cookies=None, timeout=4, load_time=2, proxies=None,
                browser='chrome', driver_path=False, screenshot=False, headless=True,
                window_size="1366,768", language="en-US,en;q=0.9", page_load_strategy="normal"):
    # use selenium to simulate browser GET request & return requests like object
    headers = headers or {}
    cookies = cookies or {}
    proxies = proxies or []
    bmap = {'firefox': FirefoxBrowser, 'chrome': ChromeBrowser}

    browser_client = None
    try:
        if browser not in bmap:
            raise ValueError("Unsupported browser provided.")

        browser_client = bmap[browser](
            timeout=timeout,
            load_time=load_time,
            driver_path=driver_path,
            headless=headless,
            window_size=window_size,
            language=language,
            page_load_strategy=page_load_strategy,
        )
        browser_client.create_driver(proxies, headers, cookies)
        return browser_client.get_request(url, screenshot)
    except Exception as e:
        LOG.debug(f'GetRequestError: {e}')
    finally:
        if browser_client:
            browser_client.close()
    return False
