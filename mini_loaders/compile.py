import json
import os
import subprocess
import sys
import itertools
from argparse import ArgumentParser
from enum import Enum
from parallel_api.api import execute_jobs_in_parallel
from compile_lib.shelf_extract_relative_symbols import extract_relative_symbol_address

local_path = os.path.dirname(__file__)
MIPS_FLAGS = " ".join(['-mgp32',
                       '-mfpxx',
                       '-mno-llsc',
                       '-mno-dsp',
                       '-mno-dspr2',
                       '-mno-smartmips',
                       '-mno-mt',
                       '-mno-mcu',
                       '-mno-eva',
                       '-mno-gpopt',
                       '-mno-load-store-pairs'])


class Arches(Enum):
    mips = 'mips'
    mipsbe = 'mipsbe'
    x32 = 'x32'
    x64 = 'x64'
    arm_x32 = 'arm_x32'
    arm_x64 = 'arm_x64'
    riscv64 = "riscv64"


arches = [arch.value for arch in Arches]

parser = ArgumentParser("Compiler")
parser.add_argument("--debug",
                    action="store_true",
                    default=False,
                    required=False,
                    help="Compile debug version")
parser.add_argument("--arches",
                    nargs="+",
                    choices=arches,
                    help="Target arches",
                    default=arches)
parser.add_argument("--action", nargs="+", choices=["clean", "make"], required=True)
options = parser.parse_args()
max_parallel_jobs = 16
CFLAGS = []
TARGET_FILES = [
    'generic_loader.c'
]


def print_header(message):
    padding = int((40 - len(message)) / 2)
    print("@" * 40)
    print("{}{}{}".format("@" * padding, message, "@" * padding))
    print("@" * 40)


if options.debug:
    CFLAGS += ["-DDEBUG"]
OUTPUT_BASE = '../outputs/mini_loader_{}.out'
RESOURCES = '../shelf/shelf/resources'
CFLAGS += ['-fno-stack-protector', '-g', '-static', '-Wno-stack-protector']
CFLAGS += ['-nolibc', '--entry=loader_main', '-nostartfiles', '-fno-plt', '-fno-pic']
CFLAGS = ' '.join(CFLAGS)
print_header("Compiling mini loaders, cflags={}".format(CFLAGS))
skip_features = {
    'x32': [['hooks', 'glibc']]
}


def should_skip_features(arch, feature):
    if arch not in options.arches:
        return True
    feature = feature.split("_")
    features_to_skip = skip_features.get(arch, [[]])
    for f_map in features_to_skip:
        found = len(f_map) > 0
        for f in f_map:
            if f not in feature:
                found = False
        if found:
            return True

    return False


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


class Compiler(object):
    def __init__(self, host, cflags, compiler_name, files=[], is_eshelf=False):
        self._gcc = "{}-gcc".format(host)
        self._objcopy = "{}-objcopy".format(host)
        self._strip = "{}-strip".format(host)
        self.cflags = cflags.split(" ")
        self.compiler_name = compiler_name
        self.compile_kwargs = None
        self.files = files
        self.is_eshelf = is_eshelf

    @staticmethod
    def execute(*cmd):
        cmd_fmt = ' '.join(['{}'.format(arg) for arg in cmd])
        print(cmd_fmt)
        return_code = subprocess.check_call(cmd_fmt, shell=True)
        if return_code != 0:
            sys.exit(return_code)

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

    def generate_structs(self, *options):
        return self.execute(
            'python',
            "-m",
            "py_elf_structs",
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
        relative_symbol_filename = os.path.join(RESOURCES, os.path.basename(
            output_file.replace(".out", ".shellcode.relative.symbols")))

        self.generate_structs(
            output_file,
            "{}.structs.json".format(resource_out)
        )
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

        symbols = extract_relative_symbol_address(
            binary_path=output_file,
            is_eshelf=self.is_eshelf
        )
        with open(relative_symbol_filename, 'w') as fp:
            json.dump(symbols, fp)

    def prepare_compile_kwargs(self, **kwargs):
        self.compile_kwargs = kwargs

    def run(self):
        self._compile(
            **self.compile_kwargs
        )


def get_compiler(host, cflags, compiler_name, files=[]):
    def cls(is_eshelf=False):
        return Compiler(
            host=host,
            cflags=cflags,
            compiler_name=compiler_name,
            files=files,
            is_eshelf=is_eshelf
        )

    return cls


MipsCompiler = get_compiler(
    host=r'mips-linux-gnu',
    cflags='{} {}'.format(CFLAGS, MIPS_FLAGS),
    compiler_name=Arches.mips.value,
    files=["mips/mips.c"]
)
MipsCompilerBE = get_compiler(
    host=r'mips-linux-gnu',
    cflags='{} {} -BE'.format(CFLAGS, MIPS_FLAGS),
    compiler_name=Arches.mipsbe.value,
    files=["mips/mips.c"]
)
IntelX32 = get_compiler(
    host=r'i686-linux-gnu',
    cflags='{} -masm=intel -fno-plt -fno-pic'.format(CFLAGS),
    compiler_name=Arches.x32.value,
    files=["intel/x32.c"]
)
IntelX64 = get_compiler(
    host=r'i686-linux-gnu',
    cflags='{} -masm=intel -fno-plt -fno-pic -m64'.format(CFLAGS),
    compiler_name=Arches.x64.value,
    files=["intel/x64.c"]

)

ArmX32 = get_compiler(
    host=r'arm-linux-gnueabi',
    cflags='{}'.format(CFLAGS),
    compiler_name=Arches.arm_x32.value,
    files=["arm/arm32.c"]
)
AARCH64 = get_compiler(
    host=r'aarch64-linux-gnu',
    cflags='{}'.format(CFLAGS),
    compiler_name=Arches.arm_x64.value,
    files=["arm/aarch64.c"]
)

RISCV64 = get_compiler(
    host=r'riscv64-linux-gnu',
    cflags='{}'.format(CFLAGS),
    compiler_name=Arches.riscv64.value,
    files=["riscv/riscv64.c"]
)

compilers = [
    MipsCompiler,
    MipsCompilerBE,
    IntelX32,
    IntelX64,
    ArmX32,
    AARCH64,
    RISCV64
]

# should perform cartesian product on the features
features = {
    # This is just a normal loader keep this
    '': {'defs': [], 'files': ['generic_loader.c'], 'supported': arches},
    'dynamic': {'defs': ['SUPPORT_DYNAMIC_LOADER'], 'files': ['generic_loader.c'], 'supported': arches},
    'hooks': {'defs': ['SUPPORT_HOOKS'], 'files': ['generic_loader.c'], 'supported': arches},

    'eshelf': {'defs': ['ESHELF', 'WITH_LIBC'],
               'files': ['generic_loader.c'] + OSAL_DEBUG_FILES,
               'supported': arches,
               "strip_flags": "--strip-all --strip-debug --strip-dwo --strip-unneeded",
               'remove_cflags': ['-nostartfiles', '--entry=loader_main', '-nolibc'],
               'is_eshelf': True}
}
# Removing generic loader key
all_feature_keys = [key for key in features.keys() if key]
all_features = []

for i in range(len(features.keys())):
    all_features += [feature for feature in itertools.combinations(all_feature_keys, i + 1)]

all_features.append(("",))  # Normal loaders no features
print(all_features)


def _clean(directory):
    for filename in os.listdir(directory):
        if "mini_loader" in filename:
            os.remove(os.path.join(directory, filename))


def clean():
    _clean('../outputs')
    _clean('../shelf/shelf/resources')


def prepare_jobs():
    jobs = []
    for compiler_cls in compilers:
        for feature_keys in all_features:
            feature_name = "_".join(feature_keys)
            attributes = {'supported': arches}  # Always set all arches to support
            for key in feature_keys:
                merge_features(attributes, features[key])
            supported = attributes.get('supported', [])
            flags = attributes.get("cflags", [])
            remove_flags = attributes.get("remove_cflags", [])
            is_eshelf = attributes.get("is_eshelf", False)
            compiler = compiler_cls(is_eshelf=is_eshelf)

            if compiler.compiler_name not in supported or should_skip_features(compiler.compiler_name, feature_name):
                print("[-] Skipping feature: {} - {}".format(
                    feature_name,
                    compiler.compiler_name
                ))
                continue
            else:
                print("[V] Compiling feature: {} - {}".format(feature_name, compiler.compiler_name))
            target_out = '{}'.format(compiler.compiler_name)
            if feature_name:
                target_out = '{}_{}'.format(compiler.compiler_name,
                                            feature_name)
            target_out = OUTPUT_BASE.format(target_out)
            compiler.prepare_compile_kwargs(
                files=attributes['files'] + compiler.files,
                output_file=target_out,
                defines=attributes['defs'],
                flags=flags,
                strip_flags=attributes.get("strip_flags"),
                remove_flags=remove_flags
            )
            jobs.append(compiler)
    return jobs


if __name__ == "__main__":
    if "clean" in options.action:
        clean()
    if "make" in options.action:

        jobs = prepare_jobs()
        entry_points = []
        for job in jobs:
            entry_points.append(job.run)
        #
        for job in jobs:
            job.run()
        # for i in range(0, int(len(jobs) / max_parallel_jobs) + 1, max_parallel_jobs):
        #    execute_jobs_in_parallel(entry_points[i:i + max_parallel_jobs])
