import os

base_file = os.path.dirname(__file__)


def get_resource(resource_name):
    path = get_resource_path(resource_name)
    with open(path, "rb") as fp:
        return fp.read()


def get_resource_path(resource_name):
    return os.path.join(base_file, resource_name)
