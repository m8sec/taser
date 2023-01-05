import os
import sys
import logging
from taser.printx import code_gen, highlight


class TaserAdapter(logging.LoggerAdapter):
    def __init__(self, logger_name='taser_cli', spacer=[]):
        self.logger = logging.getLogger(logger_name)
        self.setFormat(spacer)
        self._windows = True if os.name == 'nt' else False

    def setFormat(self, spacers):
        self._format = {}
        count = 0
        for s in spacers:
            self._format[count] = '{:<' + str(s) + '}'
            count += 1

    def msg_spacing(self, data):
        tmp_data = ''
        spacer = 0
        for value in data:
            tmp_data += (self._format[spacer].format(value) + ' ') if len(self._format) > spacer else '{} '.format(value)
            spacer += 1
        return tmp_data

    def process(self, msg, kwargs, style='bold', fg='blue', bullet=False):
        if not bullet:
            return msg, kwargs
        b = code_gen(bullet.strip(), style, fg, bg='None', windows=self._windows)
        if type(msg) == list:
            msg.insert(0, b)
            msg = self.msg_spacing(msg)
        else:
            msg = self.msg_spacing([b, msg])
        return (msg, kwargs)

    def info(self, msg, bullet='[*]', fg='blue', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, style, fg, bullet)
        self.logger.info(msg, *args, **kwargs)

    def success(self, msg, bullet='[+]', fg='green', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, style, fg, bullet)
        self.logger.info(msg, *args, **kwargs)

    def fail(self, msg, bullet='[-]', fg='red', style='bold', *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, style, fg, bullet)
        self.logger.info(msg, *args, **kwargs)

    def status(self, msg, bullet='[*]', fg='blue', style='bold', *args, **kwargs):
        msg, kwargs = self.process(highlight(msg, 'gray'), kwargs, style, fg, bullet)
        self.logger.info(msg, *args, **kwargs)

    def write(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, bullet='[!]', fg='yellow', style='bold', *args, **kwargs):
        msg, kwargs = self.process(highlight(msg, 'gray'), kwargs, style, fg, bullet)
        self.logger.warning(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        pass


def setup_cli_logger(log_level=logging.INFO, logger_name='taser_cli', spacer=[]):
    formatter = logging.Formatter('%(message)s')
    StreamHandler = logging.StreamHandler(sys.stdout)
    StreamHandler.setFormatter(formatter)

    logger = logging.getLogger(logger_name)
    logger.propagate = False
    logger.addHandler(StreamHandler)

    logger.setLevel(log_level)
    return TaserAdapter(logger_name=logger_name, spacer=spacer)


def setup_file_logger(filename, mode='a', log_level=logging.INFO, logger_name='taser_file'):
    formatter = logging.Formatter('%(message)s')
    if filename:
        fileHandler = logging.FileHandler(filename, mode=mode)
        fileHandler.setFormatter(formatter)
    else:
        fileHandler = logging.NullHandler()
    logger = logging.getLogger(logger_name)
    logger.propagate = False
    logger.addHandler(fileHandler)
    logger.setLevel(log_level)
    return logger


def setup_debug_logger():
    debug_output_string = "{} %(message)s".format(highlight('[DEBUG]', 'purple'))
    formatter = logging.Formatter(debug_output_string)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.propagate = False
    root_logger.addHandler(streamHandler)
    root_logger.setLevel(logging.DEBUG)
    return root_logger


def list_log_handlers():
    for k, v in logging.Logger.manager.loggerDict.items():
        print('+ [%s] {%s} ' % (str.ljust(k, 20), str(v.__class__)[8:-2]))
        if not isinstance(v, logging.PlaceHolder):
            for h in v.handlers:
                print('     +++', str(h.__class__)[8:-2])
