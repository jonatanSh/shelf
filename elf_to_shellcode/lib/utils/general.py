import json


def get_json(path):
    with open(path, 'r') as fp:
        return json.load(fp)
