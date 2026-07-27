import os
import socket
import logging
from os import path
from time import time
from random import choice

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait

from taser import LOG
from taser.resources.user_agents import USER_AGENTS
from taser.http.browser.browser_utils import build_requests_object
logging.getLogger('selenium').setLevel(logging.WARNING)


class ChromeBrowser:
    def __init__(self, timeout=10, load_time=2, driver_path=False, headless=True,
                 window_size="1366,768", language="en-US,en;q=0.9", page_load_strategy="normal"):
        '''
        Initialize the ChromeBrowser class with default settings.
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
        Create and configure a Chrome webdriver instance.
        '''
        proxies = proxies or []
        headers = headers or {}
        cookies = cookies or {}
        socket.setdefaulttimeout(self.timeout)

        options = Options()
        options.page_load_strategy = self.page_load_strategy
        options.accept_insecure_certs = True
        if self.headless:
            options.add_argument('--headless=new')
        options.add_argument(f'--window-size={self.window_size}')
        options.add_argument(f'--lang={self.language.split(",")[0]}')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--log-level=3')
        options.add_argument('--disable-logging')
        options.add_experimental_option('excludeSwitches', ['enable-logging'])

        # Ignore cert issues
        options.add_argument('--ignore-certificate-errors')

        # Set proxy if provided
        if proxies:
            options.add_argument(f'--proxy-server={choice(proxies)}')

        user_agent = headers.get('User-Agent', choice(USER_AGENTS))
        options.add_argument(f"--user-agent={user_agent}")
        options.add_experimental_option('prefs', {
            'intl.accept_languages': self.language,
            'profile.default_content_setting_values.notifications': 2,
        })

        # Initialize the service with the chromedriver path if provided
        service = Service(path.expanduser(self.driver_path)) if self.driver_path else Service()
        service.log_path = os.devnull  # Redirect all service logs to null to suppress output

        self.driver = webdriver.Chrome(service=service, options=options)

        # Add cookies if provided
        self.driver.get('about:blank')  # Load a blank page to set cookies
        for cookie_name, cookie_value in cookies.items():
            self.driver.add_cookie({'name': cookie_name, 'value': cookie_value})

    def get_request(self, url, screenshot=False):
        '''
        Make a request to the specified URL using the configured Chrome webdriver.
        '''
        if not self.driver:
            raise Exception("Driver not initialized. Call create_driver() first.")

        resp = False
        try:
            start_time = time()
            self.driver.get(url)
            WebDriverWait(self.driver, self.load_time).until(lambda driver: driver.execute_script("return document.readyState") == "complete")
            end_time = time()
            resp = build_requests_object(self.driver, end_time - start_time, screenshot)
        except Exception as e:
            LOG.debug(f'Web_Browser:Error::{e}')
        return resp

    def close(self):
        '''
        Close the Chrome webdriver.
        '''
        if self.driver:
            self.driver.quit()
            self.driver = None

