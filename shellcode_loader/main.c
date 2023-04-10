#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#define NUMBER_OF_OPCODES_TO_DUMP 48

void memory_dump(size_t address, size_t size) {
    printf("Dumping memory at 0x%lx\n", address);
    for(int i = 0; i < size; i ++) {
        printf("0x%02x ", *(unsigned char *)(address+i));
    }
    printf("\nMemDmpEnd\n");
}

void segfault_handler(int signal, siginfo_t *info, void *context) {
    printf("MemDmpStart Segmentation fault occurred at address: %p\n", info->si_addr);
    memory_dump((size_t)info->si_addr - ((sizeof(size_t) * (NUMBER_OF_OPCODES_TO_DUMP / 2))), NUMBER_OF_OPCODES_TO_DUMP);
    exit(1);
}

int main(int argc, char **argv, char **envp) {
    struct stat stat_buffer;
    int shellcode_fd;
    char *shellcode_buffer = NULL;
    int exit_code = 0;
    int page_size = sysconf(_SC_PAGESIZE);
    int buff_size;
    int bytes_read = 0;
    int read_chunk = _POSIX_SSIZE_MAX;
    void *start_address;
    struct sigaction sa;

    sa.sa_sigaction = segfault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);

    if (argc < 2) {
        printf("Usage main.out <shellcode>\n");
        return -1;
    }

    printf("Loading %s\n", argv[1]);

    if (stat(argv[1], &stat_buffer) != 0) {
        printf("Error stating, shellcode file\n");
        return -1;
    }

    printf("Shellcode size = %ld\n", stat_buffer.st_size);

    shellcode_fd = open(argv[1], O_RDONLY);

    if (shellcode_fd < 0) {
        printf("Read error\n");
        return -1;
    }
    buff_size = page_size;
    while (buff_size < page_size || buff_size < stat_buffer.st_size) {
        buff_size += page_size;
    }
    printf("Allocating shellcode buffer, size = %d\n", buff_size);
    shellcode_buffer = (char *) malloc(buff_size);
    if (!shellcode_buffer) {
        printf("Error allocation shellcode buffer\n");
        exit_code = -1;
        goto cleanups;
    }
    memset(shellcode_buffer, 0, buff_size);

    while (bytes_read < stat_buffer.st_size) {
        if (read_chunk > stat_buffer.st_size - bytes_read) {
            read_chunk = stat_buffer.st_size - bytes_read;
        }
        int current_read = read(shellcode_fd, shellcode_buffer + bytes_read, read_chunk);
        if (current_read < 0) {
            printf("Error reading all the shellcode, read = %d, shellcode_length=%ld, read_chunk=%d, errno=%d\n",
                   bytes_read, stat_buffer.st_size, read_chunk, errno);
            exit_code = -1;
            shellcode_buffer = NULL;
            goto cleanups;
        }
        bytes_read += current_read;
    }
    printf("Mapping new memory, size = %d\n", buff_size);

    start_address = (void *) mmap(NULL, buff_size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1,
                                  0);

    if (start_address == (void *) -1) {
        printf("Error in mprotect errcode=%d\n", errno);
        exit_code = -1;
        goto cleanups;
    }

    memcpy(start_address, shellcode_buffer, buff_size);
#ifndef NO_RWX
    mprotect(start_address, buff_size, PROT_WRITE | PROT_EXEC | PROT_READ);
#else
    mprotect(start_address, buff_size, PROT_EXEC | PROT_READ);
#endif
    printf("Jumping to shellcode, address = %p \n", start_address);
    long long value = ((int (*)(int argc, char **argv, char **envp)) start_address)(argc, argv, envp);
    printf("Shellcode returned: %llx\n", value);
    goto cleanups;


    cleanups:
    close(shellcode_fd);
    if (shellcode_buffer) {
        free(shellcode_buffer);
    }
    return exit_code;

}
