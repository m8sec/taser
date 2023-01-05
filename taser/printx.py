import os
from sys import stdout

STYLE = {'None': '0',
         'bold': '1',
         'disable': '2',
         'underline': '4',
         'blink': '5',
         'reverse': '7',
         'invisible': '8',
         'strike': '9'}

FG = {'None': '',
      'gray': ';30',
      'red': ';31',
      'green': ';32',
      'yellow': ';33',
      'blue': ';34',
      'purple': ';35',
      'cyan': ';36',
      'white': ';39'}

BG = {'None': '',
      'black': ';40',
      'red': ';41',
      'green': ';42',
      'orange': ';43',
      'blue': ';44',
      'purple': ';45',
      'cyan': ';46',
      'gray': ';47'}


def code_gen(data, style, fg, bg, windows=False):
    return data if windows else '\033[0{}{}{}m{}\033[0m'.format(STYLE[style], FG[fg], BG[bg], data)


def highlight(data, fg='blue', style='bold', bg='None'):
    return code_gen(data, style, fg, bg, windows=True if os.name == 'nt' else False)


def colored(data, fg='None', style='None', bg='None'):
    stdout.write("{}\n".format(code_gen(data, style, fg, bg)))


def bullet(data, bullet='[*] ', bullet_fg='blue', bullet_style='bold', bullet_bg='None', fg='None', style='None', bg='None'):
    # simple function to make bullet different color than text
    stdout.write("{}{}\n".format(code_gen(bullet, bullet_style, bullet_fg, bullet_bg), code_gen(data, fg, style, bg)))
