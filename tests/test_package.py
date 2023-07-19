import copy
import os.path
import subprocess
import shutil
import select
import sys
import tempfile
import glob
import shlex


def find_latest(directory_glb):
    best = (None, None)
    for filepath in glob.glob(directory_glb):
        ctime = os.path.getctime(filepath)
        if not best[0]:
            best = (filepath, ctime)
        elif best[1] < ctime:
            best = (filepath, ctime)
    return str(best[0])


temp_directory = tempfile.mkdtemp("shelf_test")
# temp_directory = '/tmp/tmpyeHlsIshelf_test/'

shelf_package = find_latest("../shelf/dist/*.tar.gz")
loader_package = find_latest("../shellcode_loader/shelf_loader/dist/*.tar.gz")
venv_directory = os.path.join(temp_directory, "venv")
venv_env = copy.deepcopy(os.environ)
venv_env['PATH'] = "{}:{}".format(os.path.join(venv_directory, "bin"), os.environ['PATH'])


class CompilationError(Exception):
    pass


class Pipe(object):
    def __init__(self, end):
        self.buffer = b""
        self.end = end

    def write(self, m):
        self.end.write(m)
        self.buffer += m

    def fileno(self):
        return self.end.fileno()


def check_output(cmd,
                 native_output=True,
                 **kwargs):
    stdout = Pipe(sys.stdout)
    stderr = Pipe(sys.stderr)
    bufsize = 1024

    if not native_output:
        stdout_pipe = subprocess.PIPE
        stderr_pipe = subprocess.PIPE
    else:
        stdout_pipe = sys.stdout
        stderr_pipe = sys.stderr
    pid = subprocess.Popen(cmd, stdout=stdout_pipe, stderr=stderr_pipe,
                           bufsize=bufsize, **kwargs)
    should_poll = 0
    # this ensures we read the last data
    while should_poll < 3:
        try:
            if not native_output:
                rlist, _, _ = select.select([pid.stdout, pid.stderr], [], [], 0.00001)
                if pid.stdout in rlist:
                    stdout.write(pid.stdout.read(bufsize))
                if pid.stderr in rlist:
                    stderr.write(pid.stderr.read(bufsize))

            if pid.poll() is not None:
                should_poll += 1
            else:
                should_poll = 0
        except KeyboardInterrupt:
            pid.kill()
    return stdout.buffer, stderr.buffer


def execute_in_virtual_environment(cmd, cwd="", native_output=True):
    return check_output(shlex.split(cmd), env=venv_env,
                        native_output=native_output,
                        cwd=os.path.join(temp_directory, cwd))


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
    check_output("python3 -m venv {}".format(venv_directory), shell=True)


def compile_resources(native=True):
    stdout, stderr = execute_in_virtual_environment("make tests EXCLUDE_LOADER=1 EXCLUDE_HELLO_HOOK=1",
                                                    cwd="tests", native_output=native)
    if stderr:
        if type(stderr) is not str:
            stderr = stderr.decode("utf-8")
        raise CompilationError(stderr)


def install_packages_from_local():
    shutil.copy(shelf_package, os.path.join(temp_directory, "shelf.tar.gz"))
    shutil.copy(loader_package, os.path.join(temp_directory, "shelf_loader.tar.gz"))
    execute_in_virtual_environment("python3 -m pip install capstone")
    execute_in_virtual_environment("python3 -m pip install pyelftools")
    execute_in_virtual_environment("python3 -m pip install lief==0.12.1")
    execute_in_virtual_environment("python3 -m pip install py_elf_structs>=1.4.2")
    print("Requirements installed ...")
    execute_in_virtual_environment("python3 -m pip install shelf.tar.gz")
    execute_in_virtual_environment("python3 -m pip install shelf_loader.tar.gz")


def run_tests():
    execute_in_virtual_environment("python3 run_tests.py --verbose", native_output=True, cwd="tests")


def test_main():
    init()
    print("[*] Trying to compile everything before installing shelf, this should fail !")
    try:
        compile_resources(native=False)
    except CompilationError:
        print("[V] Shelf probably not installed")

    print("Installing packages")
    install_packages_from_local()
    print("Compiling resources")
    compile_resources()
    print("Running tests")
    run_tests()


test_main()
