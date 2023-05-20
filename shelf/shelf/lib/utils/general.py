import json
import os.path
from shelf.lib.exceptions import InvalidJson, PathDoesNotExists
from shelf.lib import five


def get_json(path):
    if not os.path.exists(path):
        raise PathDoesNotExists(path)

    with open(path, 'r') as fp:
        try:
            return json.load(fp)
        except five.JSONDecoder:
            raise InvalidJson()


def get_binary(path):
    if not os.path.exists(path):
        raise PathDoesNotExists(path)

    with open(path, 'rb') as fp:
        return fp.read()
