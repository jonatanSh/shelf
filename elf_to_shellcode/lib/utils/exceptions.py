import logging

logger = logging.getLogger("ExceptionUtils")


class FunctionDescriptor(object):
    def __init__(self, method, *args, **kwargs):
        self.method = method
        self.args = args
        self.kwargs = kwargs

    def call(self):
        return self.method(*self.args, **self.kwargs)

    @property
    def describe(self):
        return self.method.__name__


def try_and_log(descriptor):
    assert isinstance(descriptor, FunctionDescriptor)
    try:
        return descriptor.call()
    except Exception as e:
        logger.error("Exception calling: {} error: {}".format(
            descriptor.describe,
            e
        ))
