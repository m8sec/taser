import os
import socket
import logging
from os import path
from time import time
from random import choice

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait

from taser import LOG
from taser.resources.user_agents import USER_AGENTS
from taser.http.browser.browser_utils import build_requests_object
logging.getLogger('selenium').setLevel(logging.WARNING)


class FirefoxBrowser:
    def __init__(self, timeout=10, load_time=2, driver_path=False, headless=True,
                 window_size="1366,768", language="en-US,en;q=0.9", page_load_strategy="normal"):
        '''
        Initialize the FirefoxBrowser class with default settings.
        '''
        self.timeout = timeout
        self.load_time = load_time
        self.driver_path = os.path.expanduser(driver_path) if driver_path else False
        self.headless = headless
        self.window_size = window_size
        self.language = language
        self.page_load_strategy = page_load_strategy
        self.driver = None

    def create_driver(self, proxies=None, headers=None, cookies=None):
        '''
        Create and configure a Firefox webdriver instance.
        '''
        proxies = proxies or []
        headers = headers or {}
        cookies = cookies or {}
        socket.setdefaulttimeout(self.timeout)

        options = Options()
        options.page_load_strategy = self.page_load_strategy
        options.accept_insecure_certs = True
        if self.headless:
            options.add_argument("-headless")
        width, height = self.window_size.split(",", 1)
        options.add_argument(f"--width={width}")
        options.add_argument(f"--height={height}")
        options.log.level = "fatal"

        profile = webdriver.FirefoxProfile()
        profile.set_preference("intl.accept_languages", self.language)
        profile.set_preference("dom.webnotifications.enabled", False)
        profile.set_preference("media.volume_scale", "0.0")
        profile.set_preference("security.enterprise_roots.enabled", True)

        # Set proxy if provided
        if proxies:
            p = choice(proxies)
            p = p.replace('http://', '').replace('https://', '')
            host, port = p.rsplit(':', 1)
            options.set_preference('network.proxy.type', 1)
            options.set_preference('network.proxy.http', host)
            options.set_preference('network.proxy.http_port', int(port))
            options.set_preference('network.proxy.ssl', host)
            options.set_preference('network.proxy.ssl_port', int(port))

        user_agent = headers.get('User-Agent', choice(USER_AGENTS))
        profile.set_preference("general.useragent.override", user_agent)

        # Add custom headers
        for header_name, header_value in headers.items():
            profile.set_preference(f"general.{header_name}", header_value)

        options.profile = profile

        # Initialize the service with the geckodriver path if provided
        service = Service(path.expanduser(self.driver_path)) if self.driver_path else None
        self.driver = webdriver.Firefox(service=service, options=options) if service else webdriver.Firefox(options=options)

        # Set cookies if provided
        self.driver.get('about:blank')  # Load a blank page to set cookies
        for cookie_name, cookie_value in cookies.items():
            self.driver.add_cookie({'name': cookie_name, 'value': cookie_value})

    def get_request(self, url, screenshot=False):
        '''
        Make a request to the specified URL using the configured Firefox webdriver.
        '''
        if not self.driver:
            raise Exception("Driver not initialized. Call create_driver() first.")

        resp = False
        try:
            start_time = time()
            self.driver.get(url)
            WebDriverWait(self.driver, self.load_time).until(lambda driver: driver.execute_script("return document.readyState") == "complete")
            end_time = time()
            resp = build_requests_object(self.driver, end_time-start_time, screenshot)
        except Exception as e:
            LOG.debug('Web_Browser:Error::{}'.format(e))
        return resp

    def close(self):
        '''
        Close the Firefox webdriver.
        '''
        if self.driver:
            self.driver.quit()
            self.driver = None

