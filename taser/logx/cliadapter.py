import os
import logging
from taser.printx import code_gen, highlight

class TaserAdapter(logging.LoggerAdapter):
    def __init__(self, logger_name='taser_cli', spacers=[]):
        self.logger = logging.getLogger(logger_name)
        self.setFormat(spacers)
        self.windows = False
        if os.name == 'nt':
            self.windows = True

    def setFormat(self, spacers):
        self.FORMAT={}
        count = 0
        for s in spacers:
            self.FORMAT[count] = '{:<' + str(s) + '}'
            count += 1

    def msg_spacing(self, data):
        if type(data) != list:
            return data
        tmp_data = ''
        spacer = 0
        for value in data:
            try:
                tmp_data += (self.FORMAT[spacer].format(value) + ' ')
            except:
                tmp_data += '{} '.format(value)
            spacer += 1
        return tmp_data

    def process(self, msg, kwargs, color='blue', highlight='None', style='bold', bullet=''):
        if not bullet:
            return msg, kwargs
        msg = self.msg_spacing(msg)
        return("""{}{}""".format(code_gen(bullet, style, color, highlight, self.windows), msg), kwargs)

    def info(self, msg, bullet='[*] ', fg='blue', bg='None', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, fg, bg, style, bullet)
        self.logger.info(msg, *args, **kwargs)

    def success(self, msg, bullet='[+] ', fg='green', bg='None', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, fg, bg, style, bullet)
        self.logger.info(msg, *args, **kwargs)

    def fail(self, msg, bullet='[-] ', fg='red', bg='None', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, fg, bg, style, bullet)
        self.logger.info(msg, *args, **kwargs)

    def status(self, msg, bullet='[*] ', fg='blue', bg='None', style='bold', *args, **kwargs):
        msg, kwargs = self.process(highlight(msg, 'gray', windows=self.windows), kwargs, fg, bg, style, bullet)
        self.logger.info(msg, *args, **kwargs)

    def write(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, bullet='[!] ', fg='yellow', bg='None', style='bold', *args, **kwargs):
        msg, kwargs = self.process(highlight(msg, 'gray', windows=self.windows), kwargs, fg, bg, style, bullet)
        self.logger.warning(msg, *args, **kwargs)

    def debug(self, msg, bullet='[~] ', fg='cyan', bg='None', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, fg, bg, style, bullet)
        self.logger.debug(msg, *args, **kwargs)