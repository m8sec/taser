import os
import logging
from sys import stdout

STYLE = {'none': '0',
         'bold': '1',
         'disable': '2',
         'underline': '4',
         'blink': '5',
         'reverse': '7',
         'invisible': '8',
         'strike': '9'}

FG = {'none': '',
      'gray': ';30',
      'red': ';31',
      'green': ';32',
      'yellow': ';33',
      'blue': ';34',
      'purple': ';35',
      'cyan': ';36',
      'white': ';39'}

BG = {'none': '',
      'black': ';40',
      'red': ';41',
      'green': ';42',
      'orange': ';43',
      'blue': ';44',
      'purple': ';45',
      'cyan': ';46',
      'gray': ';47'}


############################
# Custom log adapter
############################
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
        b = highlight(bullet.strip(), fg, style, bg='none', windows=self._windows)
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


############################
# Stand alone color func
############################
def highlight(data, fg='blue', style='bold', bg='none', windows=False):
    # Generates ANSI color codes
    return data if windows else '\033[0{}{}{}m{}\033[0m'.format(STYLE[style], FG[fg], BG[bg], data)


def highlight_a(data, fg='blue', style='bold', bg='none'):
    # Auto handling for Windows based OS
    return highlight(data, fg, style, bg, windows=True if os.name == 'nt' else False)


def color(data, fg='blue', style='bold', bg='none', windows=False):
    # Print colored output
    stdout.write("{}\n".format(highlight(data, fg, style, bg, windows)))


def bullet(data, bullet='[*] ', bullet_fg='blue', bullet_style='bold', bullet_bg='none', fg='none', style='none', bg='none'):
    # Make bullet different color from text and print <- oh you fancy huh?
    stdout.write("{}{}\n".format(highlight(bullet, bullet_fg, bullet_style, bullet_bg), highlight(data, fg, style, bg)))


############################
# Setup logger support
############################
def setup_cli_logger(log_level=logging.INFO, logger_name='taser_cli', auto_adapter=True, spacer=[]):
    formatter = logging.Formatter('%(message)s')
    StreamHandler = logging.StreamHandler(stdout)
    StreamHandler.setFormatter(formatter)

    logger = logging.getLogger(logger_name)
    logger.propagate = False
    logger.addHandler(StreamHandler)

    logger.setLevel(log_level)
    return TaserAdapter(logger_name=logger_name, spacer=spacer) if auto_adapter else logger


def setup_file_logger(filename, mode='w', log_level=logging.INFO, logger_name='taser_file'):
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
    debug_output_string = "[Debug] %(message)s"
    formatter = logging.Formatter(debug_output_string)
    streamHandler = logging.StreamHandler(stdout)
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
