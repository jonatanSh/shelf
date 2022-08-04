#include <stdarg.h>
#ifndef OSAL_LIBC
    #include <unistd.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>

#else
    #include "../osals/linux/syscalls_wrapper/unistd.h"
    #include "../osals/string.h"
#endif
#include "../osals/sprintf.h"


#define MAX_DEBUG_BUFFER 0xffff
#define TRACE_FORMAT "[ELF_FEATURES:INFO] %s %s(line:%u):\x00"

struct elf_information_struct {
    size_t elf_header_size;
    size_t loader_size;
};
struct relocation_table {
    size_t magic;
    size_t total_size;
    struct elf_information_struct elf_information;
};
void loader_main(
    int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic,
    size_t pc);

int get_elf_information(struct relocation_table ** info);


void write_out(char * msg) {
#ifndef OSAL_LIBC
    write(1, msg, strlen(msg));
#else
    sys_write(1, msg, strlen(msg));
#endif
}


void trace_handler(const char * file, const char * func, unsigned int line, char * trace_format, const char* fmt, ...) {
	va_list ap;
	char debug_buffer[MAX_DEBUG_BUFFER];


    my_sprintf(debug_buffer, 
        trace_format,
        file,
        func,
        line);

    va_start (ap, fmt);
    my_vsprintf(debug_buffer + strlen(debug_buffer),
        fmt,
        ap);
    va_end (ap);
    write_out(debug_buffer);
}
#define TRACE(fmt, ...) trace_handler(__FILE__, __FUNCTION__ ,__LINE__, TRACE_FORMAT, fmt, ##__VA_ARGS__)


void say_hi() {
    TRACE("Hi\n");
}

void say_hello() {
    TRACE("Hello\n");
}

typedef void (*function_t)();

static const function_t funcs[] = {
    &say_hi,
    &say_hello
};

void test_jump_table(int random) {

    switch(random) {
        case 1:
            TRACE("Case is 1\n");
        default:
            TRACE("Case is default\n");
    }
}

void test_global_ptr_arrays() {

	for(int i = 0; i < sizeof(funcs) / sizeof(void *); i++) {
		function_t func = funcs[i];
		func();
	}
}

#define ERROR -1
#define SUCCESS 1



void main(int random) {
    int status;

    TRACE("Hello from shellcode!\n");
    TRACE("Testing jump tables\n");
    test_jump_table(random);
    TRACE("Testing global ptr arrays\n");
    test_global_ptr_arrays();
    struct relocation_table * info;

#ifdef DYNAMIC_SUPPORT
    TRACE("Calling get elf information, testing dynamic shellcode\n");
    TRACE("Arch support dynamic relocations, testing dynamic objects\n");
    status=get_elf_information(&info);
    if(status == ERROR) {
        TRACE("Error while calling get elf information\n");
        goto error;
    }
    TRACE("get_elf_information status=%x\n", status);
    TRACE("Got elf information: magic=%x header size = %x, loader size = %x\n",
    info->magic,
    info->elf_information.elf_header_size, 
    info->elf_information.loader_size);
#endif
error:
    return;
}

