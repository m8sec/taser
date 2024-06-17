import socket
import logging
from os import path
from time import time
from random import choice
from types import SimpleNamespace

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

from taser import LOG
from taser.http import URLParser
from taser.utils import file_collision_check
from taser.resources.user_agents import USER_AGENTS
logging.getLogger('selenium').setLevel(logging.WARNING)


def web_browser(url, headers={}, cookies={}, timeout=10, load_time=2, screenshot=False, proxies=[], driver_path=False):
    '''
    Make HTTP Requests with Selenium & Chrome webdriver. returns requests-like object for parsing

    Manually Install Chrome Driver:
        1) get chromedriver - http://chromedriver.chromium.org/downloads
        2) Make sure chromedriver matches version of chrome running
        3) Add to PATH or define driver_path parameter
    '''
    resp = False
    socket.setdefaulttimeout(timeout)

    options = Options()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument('--silent')
    options.add_argument('--headless=new')
    options.add_argument('--log-level=3')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-application-cache')
    options.add_argument('ignore-certificate-errors')

    if proxies:
        p = get_proxy(proxies)
        options.add_argument(f'--proxy-server={p}')

    if driver_path:
        service = Service(path.expanduser(driver_path))     
        driver = webdriver.Chrome(service=service, options=options)
    else:
        # Assume chromedriver in users PATH 
        driver = webdriver.Chrome(options=options)

    # Add headers
    for header_name, header_value in headers.items():
        options.add_argument(f"--header={header_name}: {header_value}")

    # Randomize user-agent
    if 'User-Agent' not in headers.keys():
        options.add_argument("user-agent={}".format(choice(USER_AGENTS)))

    # Add cookies:
    for cookie_name, cookie_value in cookies.items():
        driver.add_cookie({'name': cookie_name, 'value': cookie_value})

    try:
        start_time = time()
        driver.get(url)
        driver.set_script_timeout(load_time)
        end_time = time()

        resp = build_requests_object(driver, end_time-start_time, screenshot)
    
    except Exception as e:
        LOG.debug('Web_Browser:Error::{}'.format(e))
    finally:
        driver.quit()
    return resp


def get_proxy(proxies):
    # Take in list value and return random proxy formated for python-requests
    if not proxies:
        return {}
    tmp = choice(proxies)
    return {"http": tmp, "https": tmp}


def build_requests_object(driver, elapsed_time=False, screenshot=False):
    fname = False
    
    # Save screenshot
    if screenshot:
        fname = file_collision_check(path.join(screenshot, URLParser.extract_subdomain(url)), ext='png')
        driver.save_screenshot(fname)
        resp.screenshot = fname


    return SimpleNamespace(
        # @todo, selenium-wire depreciated
        history=[],
        headers = {},
        status_code = False,

        driver=driver,
        url=driver.current_url,
        screenshot=fname,
        elapsed=elapsed_time,
        title=driver.title if driver else '',
        text=driver.page_source if driver else '',
        cookies=driver.get_cookies() if driver else {},
        content=driver.page_source.encode('utf-8') if driver else ''
    )
