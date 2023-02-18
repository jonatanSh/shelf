#ifndef MINI_LOADER_EXTERNAL_DEFS
#define MINI_LOADER_EXTERNAL_DEFS

/*
    This file contain external defines for the mini loader
*/
#define MAX_NUMBER_OF_HOOKS 1

struct elf_information_struct {
    size_t elf_header_size;
    size_t loader_size;
};

struct hook {
    size_t relative_address;
};

struct mini_loader_hooks_descriptor { 
    size_t size_of_hook_shellcode_data;
    struct hook startup_hooks[MAX_NUMBER_OF_HOOKS];
};
struct relocation_table {
    size_t magic;
    size_t total_size;
    size_t header_size;
    struct elf_information_struct elf_information;
#ifdef SUPPORT_HOOKS
    struct mini_loader_hooks_descriptor hooks;
#endif
};
void loader_main(
    int argc,
    char ** argv,
    char ** envp,
    size_t loader_magic,
    size_t pc);

int get_elf_information(struct relocation_table ** info);
// External defines
#define OK 1
#define ERROR -1

/* 
    The following are the possible error codes returned from the mini loader
*/
#define MAGIC_NOT_FOUND (1 << 1)
#define INVALID_MAGIC (1 << 2)
#define INVALID_ATTRIBUTE (1 << 3)

#endif // MINI_LOADER_EXTERNAL_DEFS