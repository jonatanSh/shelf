#include "./no_libc.h"
#include "tests.h"
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

long long int main() {
    struct elf_information_struct info;
    sys_write(1, "Hello\n", 6);
    #ifdef DYNAMIC_SUPPORT
        get_elf_information(&info);
    #endif
    return TEST_OUT;
}