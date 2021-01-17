import logging

class DBHandler(logging.Handler):
    '''Pass designated DB object with conn established and exec method. Due
    to this implementation, the DB connection needs to be tied directly to the
    class object. '''
    def __init__(self, db_obj, *args, **kwargs):
        super().__init__()
        self.db = db_obj

    def emit(self,record):
        data = self.format(record)
        self.db.exec(data)


class DBAdapter(logging.LoggerAdapter):
    '''Adapter responsible for modifying DB query data.
    If needed, use inheritance to create custom methods
    for handling data inputs.'''
    def __init__(self, logger_name='taser_db'):
        self.logger = logging.getLogger(logger_name)

    def process(self, msg, kwargs):
        return msg, kwargs

    def query(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs)
        self.logger.info(msg, *args, **kwargs)