import os
import subprocess

TARGET_FILES = [
    'generic_loader.c'
]
OUTPUT_BASE = '../outputs/mini_loader_{}.out'
RESOURCES = '../elf_to_shellcode/resources'
features = {
    # This is just a normal loader keep this
    '': {'defs': [], 'files': ['generic_loader.c']},
    'dynamic': {'defs': ['SUPPORT_DYNAMIC_LOADER'], 'files': ['generic_loader.c']},
    'glibc': {'defs': ['SUPPORT_START_FILES'], 'files': ['generic_loader.c'], 'supported': ['x32']},

}


class Compiler(object):
    def __init__(self, gcc, objcopy, cflags, compiler_name):
        self._gcc = gcc
        self._objcopy = objcopy
        self.cflags = cflags.split(" ")
        self.compiler_name = compiler_name

    @staticmethod
    def execute(*cmd):
        cmd_fmt = ' '.join(['{}'.format(arg) for arg in cmd])
        print(cmd_fmt)
        subprocess.check_call(cmd_fmt, shell=True)

    def gcc(self, *options):
        return self.execute(
            self._gcc,
            *(self.cflags + list(options))
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

    def compile(self, files, output_file, defines=[]):
        # 	$(CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips.out
        args = ['-D{}'.format(d) for d in defines]
        args += files
        args += ['-o', output_file]
        self.gcc(*args)
        resource_out = os.path.join(RESOURCES, os.path.basename(output_file.replace(".out", ".shellcode")))
        symbol_filename = os.path.join(RESOURCES, os.path.basename(output_file.replace(".out", ".shellcode.symbols")))

        self.objcopy(
            "-j",
            '.text',
            '-O',
            'binary',
            output_file,
            resource_out
        )

        self.readelf(
            '-s',
            output_file,
            '>',
            symbol_filename
        )


MipsCompiler = Compiler(
    gcc=r'mips-linux-gnu-gcc',
    objcopy=r'mips-linux-gnu-objcopy',
    cflags='-g -static -Wno-stack-protector -nolibc -nostartfiles --entry=loader_main',
    compiler_name="mips"
)
MipsCompilerBE = Compiler(
    gcc=r'mips-linux-gnu-gcc',
    objcopy=r'mips-linux-gnu-objcopy',
    cflags='-g -static -Wno-stack-protector -nolibc -nostartfiles --entry=loader_main -BE',
    compiler_name="mipsbe"
)
IntelX32 = Compiler(
    gcc=r'i686-linux-gnu-gcc',
    objcopy=r'i686-linux-gnu-objcopy',
    cflags='-static -nolibc -nostartfiles -g -Wno-stack-protector -masm=intel -fno-plt -fno-pic --entry=loader_main',
    compiler_name="x32"
)
IntelX64 = Compiler(
    gcc=r'i686-linux-gnu-gcc',
    objcopy=r'i686-linux-gnu-objcopy',
    cflags='-static -nolibc -nostartfiles -g -Wno-stack-protector -masm=intel -fno-plt -fno-pic --entry=loader_main -m64',
    compiler_name="x64"
)

ArmX32 = Compiler(
    gcc=r'arm-linux-gnueabi-gcc',
    objcopy=r'arm-linux-gnueabi-objcopy',
    cflags='--entry=loader_main -static -nolibc -nostartfiles -g -Wno-stack-protector -fno-plt -fno-pic',
    compiler_name="arm_x32"
)
AARCH64 = Compiler(
    gcc=r'aarch64-linux-gnu-gcc',
    objcopy=r'aarch64-linux-gnu-objcopy',
    cflags='--entry=loader_main -static -nolibc -nostartfiles -g -Wno-stack-protector -fno-plt -fno-pic',
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
            defines=attributes['defs']
        )
