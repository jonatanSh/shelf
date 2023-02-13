import os
import subprocess
import sys
from multiprocessing import Process
from time import sleep
import itertools

CFLAGS = []
TARGET_FILES = [
    'generic_loader.c'
]


def print_header(message):
    padding = (40 - len(message)) / 2
    print("@" * 40)
    print("{}{}{}".format("@" * padding, message, "@" * padding))
    print("@" * 40)


jobs_count = 16
if len(sys.argv) < 2:
    print("Usage compile.py <release|debug> <optional|jobs>")
    sys.exit(1)
if len(sys.argv) > 2:
    jobs_count = int(sys.argv[2])

assert sys.argv[1].strip() in ['debug', 'release'], 'error got invalid argument: {}'.format(sys.argv[1])

if sys.argv[1].strip() == 'debug':
    CFLAGS += ["-DDEBUG"]

OUTPUT_BASE = '../outputs/mini_loader_{}.out'
RESOURCES = '../elf_to_shellcode/resources'
CFLAGS += ['-fno-stack-protector', '-g', '-static', '-Wno-stack-protector']
CFLAGS += ['-nolibc', '--entry=loader_main', '-nostartfiles', '-fno-plt', '-fno-pic']
CFLAGS = ' '.join(CFLAGS)
print_header("Compiling mini loaders, cflags={}".format(CFLAGS))


def cfiles(directory):
    return [os.path.join(directory, filename) for filename in os.listdir(directory)
            if filename.endswith(".c")]


OSAL_BASE = cfiles('../osals')
LINUX_OSAL_FILES = OSAL_BASE
LINUX_OSAL_FILES += cfiles("../osals/linux/")
LINUX_OSAL_FILES += cfiles("../osals/linux/syscalls_wrapper/")
LINUX_OSAL_FILES += cfiles("../osals/linux/syscalls_wrapper/sys")
OSAL_DEBUG_FILES = [os.path.join("../osals/linux/debug.c")]


def merge_features(first_dict, second_dict):
    for key in second_dict:
        # Special key, drop support for features
        if key == 'supported':
            s1 = set(first_dict.get('supported', set()))
            s2 = set(second_dict.get('supported', set()))
            supported = s1 & s2
            first_dict['supported'] = supported
        elif key not in first_dict:
            first_dict[key] = second_dict[key]
        else:
            if type(first_dict[key]) is str:
                first_dict[key] += " " + second_dict[key]
            elif type(first_dict[key]) is list:
                first_dict[key] = list(set(first_dict[key]) | set(second_dict[key]))
            else:
                raise Exception("No Merge for type: {}".format(
                    type(first_dict[key])
                ))


class Compiler(Process):
    def __init__(self, host, cflags, compiler_name):
        self._gcc = "{}-gcc".format(host)
        self._objcopy = "{}-objcopy".format(host)
        self._strip = "{}-strip".format(host)
        self.cflags = cflags.split(" ")
        self.compiler_name = compiler_name
        self.compile_kwargs = None
        self.is_running = False
        super(Compiler, self).__init__()

    @staticmethod
    def execute(*cmd):
        cmd_fmt = ' '.join(['{}'.format(arg) for arg in cmd])
        print(cmd_fmt)
        subprocess.check_call(cmd_fmt, shell=True)

    def gcc(self, flags, remove_flags, *options):
        flags = (self.cflags + flags)
        for flag in remove_flags:
            if flag in flags:
                flags.remove(flag)
        return self.execute(
            self._gcc,
            *(flags + list(options))
        )

    def objcopy(self, *options):
        return self.execute(
            self._objcopy,
            *options
        )

    def readelf(self, *options):
        return self.execute(
            'readelf',
            *options
        )

    def strip(self, *options):
        return self.execute(
            self._strip,
            *options
        )

    def _compile(self, files, output_file, defines, flags, strip_flags, remove_flags):
        # 	$(CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips.out
        args = ['-D{}'.format(d) for d in defines]
        args += files
        args += ['-o', output_file]
        self.gcc(flags, remove_flags, *args)
        resource_out = os.path.join(RESOURCES, os.path.basename(output_file.replace(".out", ".shellcode")))
        symbol_filename = os.path.join(RESOURCES, os.path.basename(output_file.replace(".out", ".shellcode.symbols")))

        if not strip_flags:
            self.objcopy(
                "-j",
                '.text',
                '-O',
                'binary',
                output_file,
                resource_out
            )
        else:
            self.strip(
                *(strip_flags.split(" ") + [output_file, "-o", resource_out])
            )

        self.readelf(
            '-s',
            '--wide',
            output_file,
            '>',
            symbol_filename
        )

    def prepare_compile_kwargs(self, **kwargs):
        self.compile_kwargs = kwargs

    def run(self):
        self._compile(
            **self.compile_kwargs
        )

    def start(self):
        self.is_running = True
        super(Compiler, self).start()

    @property
    def terminated(self):
        return self.exitcode is not None


MipsCompiler = Compiler(
    host=r'mips-linux-gnu',
    cflags='{}'.format(CFLAGS),
    compiler_name="mips"
)
MipsCompilerBE = Compiler(
    host=r'mips-linux-gnu',
    cflags='{} -BE'.format(CFLAGS),
    compiler_name="mipsbe"
)
IntelX32 = Compiler(
    host=r'i686-linux-gnu',
    cflags='{} -masm=intel -fno-plt -fno-pic'.format(CFLAGS),
    compiler_name="x32"
)
IntelX64 = Compiler(
    host=r'i686-linux-gnu',
    cflags='{} -masm=intel -fno-plt -fno-pic -m64'.format(CFLAGS),
    compiler_name="x64"
)

ArmX32 = Compiler(
    host=r'arm-linux-gnueabi',
    cflags='{}'.format(CFLAGS),
    compiler_name="arm_x32"
)
AARCH64 = Compiler(
    host=r'aarch64-linux-gnu',
    cflags='{}'.format(CFLAGS),
    compiler_name="arm_x64"
)

compilers = [
    MipsCompiler,
    MipsCompilerBE,
    IntelX32,
    IntelX64,
    ArmX32,
    AARCH64
]

arches = [compiler.compiler_name for compiler in compilers]

# should perform cartesian product on the features
features = {
    # This is just a normal loader keep this
    '': {'defs': [], 'files': ['generic_loader.c'], 'supported': arches},
    'dynamic': {'defs': ['SUPPORT_DYNAMIC_LOADER'], 'files': ['generic_loader.c'], 'supported': arches},
    'glibc': {'defs': ['SUPPORT_START_FILES'], 'files': ['generic_loader.c'], 'supported': ['x32']},
    'eshelf': {'defs': ['ESHELF', 'WITH_LIBC'],
               'files': ['generic_loader.c'] + OSAL_DEBUG_FILES,
               'supported': [
                   'x64',
                   'x32',
                   'mipsbe',
                   'mips',
                   'arm_x32',
               ],
               "strip_flags": "--strip-all --strip-debug --strip-dwo --strip-unneeded",
               'remove_cflags': ['-nostartfiles', '--entry=loader_main', '-nolibc']}
}
# Removing generic loader key
all_feature_keys = [key for key in features.keys() if key]
all_features = []

for i in range(len(features.keys())):
    all_features += [feature for feature in itertools.combinations(all_feature_keys, i + 1)]


def clean():
    for filename in os.listdir("../outputs"):
        if "mini_loader" in filename:
            os.remove(os.path.join("../outputs", filename))


def terminate_all(jobs):
    for job in jobs:
        try:
            job.terminate()
        except:
            pass

def start_jobs(jobs, max_parallel_jobs=16):
    exit_code = 0
    while len(jobs) > 0:
        try:
            started_jobs = 0
            jobs_to_remove = []
            for job in jobs:
                if job.terminated:
                    max_parallel_jobs -= 1
                    exit_code = job.exitcode
                    jobs_to_remove.append(job)
                    if exit_code != 0:
                        terminate_all(jobs)
                        return exit_code

                elif started_jobs < max_parallel_jobs:
                    if not job.is_running:
                        job.start()
                        max_parallel_jobs += 1
                sleep(0.1)
            for job in jobs_to_remove:
                if job in jobs:
                    jobs.remove(job)
        except KeyboardInterrupt:
            terminate_all(jobs)
            return -1
    terminate_all(jobs)
    return exit_code


def prepare_jobs():
    jobs = []
    for compiler in compilers:
        for feature_keys in all_features:
            feature_name = "_".join(feature_keys)
            attributes = {'supported': arches}  # Always set all arches to support
            for key in feature_keys:
                merge_features(attributes, features[key])
            supported = attributes.get('supported', [])
            flags = attributes.get("cflags", [])
            remove_flags = attributes.get("remove_cflags", [])
            if compiler.compiler_name not in supported:
                print("Skipping feature: {} for compiler: {}".format(
                    feature_name,
                    compiler.compiler_name
                ))
                continue
            target_out = '{}'.format(compiler.compiler_name)
            if feature_name:
                target_out = '{}_{}'.format(compiler.compiler_name,
                                            feature_name)
            target_out = OUTPUT_BASE.format(target_out)
            compiler.prepare_compile_kwargs(
                files=attributes['files'],
                output_file=target_out,
                defines=attributes['defs'],
                flags=flags,
                strip_flags=attributes.get("strip_flags"),
                remove_flags=remove_flags
            )
            jobs.append(compiler)
    return jobs


if __name__ == "__main__":
    print("Compiling, max parallel jobs = %d" % jobs_count)
    clean()
    jobs = prepare_jobs()
    start_jobs(jobs, max_parallel_jobs=jobs_count)
