import asyncio
import concurrent.futures
from taser import printx
from taser.proto.http import WebSession

class AsyncHTTP():
    '''
    Utilize asyncio to send concurrent HTTP requests.
    uses WebSessions class to maintain a persistent
    TCP connection with 'Keep-Alive' headers.
    '''
    def __init__(self, timeout):
        self.timeout = timeout

    def request_handler(self, url):
        return self.session.get_request(url, timeout=12, proxies=[])

    def response_handler(self, resp):
        printx.bullet("{} => {}".format(resp.request.url, resp.get_statuscode(resp)))

    async def execution(self, urls, max_workers=50):
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            loop = asyncio.get_event_loop()
            coros = []
            for url in urls:
                coros.append(loop.run_in_executor(executor, self.request_handler, url))

            for resp in await asyncio.gather(*coros):
                self.response_handler(resp)

    def launcher(self, urls, keep_alive=True):
        self.session = WebSession(keep_alive=keep_alive)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.execution(urls))
        self.session.close()