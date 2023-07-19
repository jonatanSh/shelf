class ShelfException(Exception):
    def __str__(self, **kwargs):
        return "{}({})".format(
            self.__class__.__name__,
            ",".join("{}={}".format(k, v) for k, v in kwargs.items())
        )


class PathDoesNotExists(ShelfException):
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return super(PathDoesNotExists, self).__str__(
            path=self.path
        )


class InvalidJson(ShelfException):
    pass


class AddressNotInShelf(ShelfException):
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return super(AddressNotInShelf, self).__str__(
            error="Address not in memory",
            address=self.address
        )


class MiniLoaderNotFound(ShelfException):
    def __str__(self):
        return super(self).__str__(
            error="Mini loader was not found in dump",
        )
