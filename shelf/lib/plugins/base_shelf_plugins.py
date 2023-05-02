from logging import getLogger


class BaseShelfPlugin(object):
    def __init__(self, shelf):
        self.shelf = shelf
        self.logger = getLogger(self.__class__.__name__)
