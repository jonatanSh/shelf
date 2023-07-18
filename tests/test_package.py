import os.path
import subprocess
import shutil
import tempfile

temp_directory = tempfile.mkdtemp("shelf_test")
venv_directory = os.path.join(temp_directory, "venv")

# Cmd: cd ./tests && make tests EXCLUDE_LOADER=1 EXCLUDE_HELLO_HOOK=1
def init():
    print("[*] Temp directory: {}".format(temp_directory))
    shutil.copytree("../makefiles", os.path.join(temp_directory, "makefiles"))
    shutil.copytree("../tests", os.path.join(temp_directory, "tests"))
    shutil.copytree("../hooks", os.path.join(temp_directory, "hooks"))
    shutil.copytree("../osals", os.path.join(temp_directory, "osals"))
    shutil.copytree("../mini_loaders", os.path.join(temp_directory, "mini_loaders"))
    shutil.copytree("../headers", os.path.join(temp_directory, "headers"))
    print("[*] Resources copied")
    print("Creating virtual env")
    subprocess.check_output("python3 -m venv {}".format(venv_directory), shell=True)

init()
