#include <stdarg.h>
#include "tests.h"
#if defined(WITH_LIBC) || !defined(OSAL_LIBC)
    #include <unistd.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>

#else
    #include "../osals/linux/syscalls_wrapper/unistd.h"
    #include "../osals/string.h"
    #include "../osals/sprintf.h"
#endif
#include "../headers/mini_loader.h"

static int static_variable = 1;

#define MAX_DEBUG_BUFFER 0xffff
#define TRACE_FORMAT "[ELF_FEATURES:INFO] %s %s(line:%u):\x00"

void write_out(char * msg) {
    write(1, msg, strlen(msg));
}


void trace_handler(const char * file, const char * func, unsigned int line, char * trace_format, const char* fmt, ...) {
	va_list ap;
	char debug_buffer[MAX_DEBUG_BUFFER];


    sprintf(debug_buffer,
        trace_format,
        file,
        func,
        line);

    va_start (ap, fmt);
    vsprintf(debug_buffer + strlen(debug_buffer),
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

void test_jump_table(size_t random) {

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

long long int main(void * main_address, int argc, char ** argv, int total_args) {
    int status;
    TRACE("main address=%x, argc=%x, argv=%x, total_args=%d\n",
        main_address, argc, argv, total_args);
#ifndef ESHELF
    TRACE("Elf in shellcode mode!\n");
    if(argc != 2) {
        TRACE("Failure, incorrect argc\n");
        goto error;
    }
    TRACE("Argv[0] = %s, argv[1] = %s\n", argv[0], argv[1]);
#else
    TRACE("Elf in eshelf mode !\n");
#endif
    TRACE("Testing static variables, static_variable=%d, changing to 2\n", static_variable);
    static_variable = 2;
    TRACE("Testing static variables, static_variable=%d\n", static_variable);
    TRACE("Hello from shellcode!\n");
    TRACE("Testing jump tables\n");
    test_jump_table((size_t)main_address);
    TRACE("Testing global ptr arrays\n");
    test_global_ptr_arrays();
    struct relocation_table * info;

#ifdef DYNAMIC_SUPPORT
    TRACE("Calling get elf information, testing dynamic shellcode\n");
    TRACE("Arch support dynamic relocations, testing dynamic objects\n");
    TRACE("Dynamic function is at %x\n", get_elf_information);
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
    TRACE("__Test_output_Success\n");

error:
    return TEST_OUT;
}

