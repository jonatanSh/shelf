#include "./no_libc.h"

typedef unsigned int size_t;

struct elf_information_struct {
    size_t elf_header_size;
};

void loader_main(
    int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic,
    size_t pc);

int get_elf_information();

void main() {
    struct elf_information_struct info;
    print_out("Hello\n", 6);
    #ifdef DYNAMIC_SUPPORT
        get_elf_information(&info);
    #endif
}