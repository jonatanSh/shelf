class ExceptionBase(Exception):
    def __str__(self, **kwargs):
        return "{}({})".format(
            self.__class__.__name__,
            ",".join("{}={}".format(k, v) for k, v in kwargs.items())
        )


class PathDoesNotExists(ExceptionBase):
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return super(PathDoesNotExists, self).__str__(
            path=self.path
        )


class InvalidJson(ExceptionBase):
    pass
