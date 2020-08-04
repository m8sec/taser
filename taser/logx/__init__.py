import sys
import logging
from taser.logx.cliadapter import TaserAdapter
from taser.logx.dbhandler import DBHandler, DBAdapter

def setup_consoleLogger(log_level=logging.INFO, logger_name='taser_cli', adapter=TaserAdapter, spacers=[]):
    formatter = logging.Formatter('%(message)s')
    StreamHandler = logging.StreamHandler(sys.stdout)
    StreamHandler.setFormatter(formatter)
    logger = logging.getLogger(logger_name)
    logger.propagate = False
    logger.addHandler(StreamHandler)
    logger.setLevel(log_level)
    return adapter(logger_name, spacers)

def setup_fileLogger(filename, mode='a', log_level=logging.INFO, logger_name='taser_file'):
    '''Create standard logger for file output'''
    formatter = logging.Formatter('%(message)s')
    if filename:
        fileHandler = logging.FileHandler(filename, mode=mode)
        fileHandler.setFormatter(formatter)
    else:
        fileHandler = logging.NullHandler()
    logger = logging.getLogger(logger_name)
    logger.addHandler(fileHandler)
    logger.setLevel(log_level)
    return logger

def setup_dbLogger(db_obj, log_level=logging.INFO, logger_name='taser_db', adapter=DBAdapter):
    '''Use python logging with local sqlite database to easily insert program output'''
    formatter = logging.Formatter('%(message)s')
    if db_obj:
        dbHandler = DBHandler(db_obj)
        dbHandler.setFormatter(formatter)
    else:
        dbHandler = logging.NullHandler()
    logger = logging.getLogger(logger_name)
    logger.addHandler(dbHandler)
    logger.setLevel(log_level)
    return adapter(logger_name)

def debug_args(args, logger):
    '''Debug function to print CMD arguments on debug'''
    for k in args.__dict__:
        if args.__dict__[k] is not None:
            logger.debug(['args.{}'.format(k), '::: {}'.format(args.__dict__[k])])