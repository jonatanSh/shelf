import os
import subprocess

TARGET_FILES = [
    'generic_loader.c'
]
OUTPUT_BASE = '../outputs/mini_loader_{}.out'
RESOURCES = '../elf_to_shellcode/resources'
CFLAGS = ['-fno-stack-protector', '-g', '-static', '-Wno-stack-protector']
CFLAGS += ['-nolibc', '-nostartfiles', '-fno-plt', '-fno-pic']
CFLAGS = ' '.join(CFLAGS)

def cfiles(directory):
    return [os.path.join(directory, filename) for filename in os.listdir(directory)
            if filename.endswith(".c")]


OSAL_BASE = cfiles('../osals')
LINUX_OSAL_FILES = OSAL_BASE
LINUX_OSAL_FILES += cfiles("../osals/linux/")
LINUX_OSAL_FILES += cfiles("../osals/linux/syscalls_wrapper/")
LINUX_OSAL_FILES += cfiles("../osals/linux/syscalls_wrapper/sys")

# should perform cartesian product on the features
features = {
    # This is just a normal loader keep this
    '': {'defs': [], 'files': ['generic_loader.c']},
    'dynamic': {'defs': ['SUPPORT_DYNAMIC_LOADER'], 'files': ['generic_loader.c']},
    'glibc': {'defs': ['SUPPORT_START_FILES'], 'files': ['generic_loader.c'], 'supported': ['x32']},
    'eshelf': {'defs': ['ESHELF'],
                'files': ['generic_loader.c'] + LINUX_OSAL_FILES,
                'cflags': ['-I../osals/linux/', '-I../osals'],
                'supported': [
                    'x64',
                ],
                "strip_flags": "--strip-all --strip-debug --strip-dwo --strip-unneeded"}
}


class Compiler(object):
    def __init__(self, host, cflags, compiler_name):
        self._gcc = "{}-gcc".format(host)
        self._objcopy = "{}-objcopy".format(host)
        self._strip = "{}-strip".format(host)
        self.cflags = cflags.split(" ")
        self.compiler_name = compiler_name

    @staticmethod
    def execute(*cmd):
        cmd_fmt = ' '.join(['{}'.format(arg) for arg in cmd])
        print(cmd_fmt)
        subprocess.check_call(cmd_fmt, shell=True)

    def gcc(self, flags, *options):
        return self.execute(
            self._gcc,
            *(self.cflags + flags + list(options))
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

    def compile(self, files, output_file, defines, flags, strip_flags):
        # 	$(CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips.out
        args = ['-D{}'.format(d) for d in defines]
        args += files
        args += ['-o', output_file]
        self.gcc(flags, *args)
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


MipsCompiler = Compiler(
    host=r'mips-linux-gnu',
    cflags='{} --entry=loader_main'.format(CFLAGS),
    compiler_name="mips"
)
MipsCompilerBE = Compiler(
    host=r'mips-linux-gnu',
    cflags='{} --entry=loader_main -BE'.format(CFLAGS),
    compiler_name="mipsbe"
)
IntelX32 = Compiler(
    host=r'i686-linux-gnu',
    cflags='{} -masm=intel -fno-plt -fno-pic --entry=loader_main'.format(CFLAGS),
    compiler_name="x32"
)
IntelX64 = Compiler(
    host=r'i686-linux-gnu',
    cflags='{} -masm=intel -fno-plt -fno-pic --entry=loader_main -m64'.format(CFLAGS),
    compiler_name="x64"
)

ArmX32 = Compiler(
    host=r'arm-linux-gnueabi',
    cflags='--entry=loader_main {}'.format(CFLAGS),
    compiler_name="arm_x32"
)
AARCH64 = Compiler(
    host=r'aarch64-linux-gnu',
    cflags='--entry=loader_main {}'.format(CFLAGS),
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

for compiler in compilers:
    for feature_name, attributes in features.items():
        supported = attributes.get('supported')
        flags = attributes.get("cflags", [])
        if supported:
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
        compiler.compile(
            files=attributes['files'],
            output_file=target_out,
            defines=attributes['defs'],
            flags=flags,
            strip_flags=attributes.get("strip_flags")
        )
