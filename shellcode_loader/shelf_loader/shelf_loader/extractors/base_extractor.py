class BaseExtractor(object):
    def __init__(self, stream, args, extractor_data):
        self.stream = stream
        self.args = args
        self.extractor_data = extractor_data
