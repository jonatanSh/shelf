#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "sprintf.h"

#define MAX_DEBUG_BUFFER 0xffff
#define TRACE_FORMAT "[INFO] %s %s(line:%u):"

struct elf_information_struct {
    size_t elf_header_size;
    size_t loader_size;
};

void loader_main(
    int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic,
    size_t pc);

int get_elf_information();


void write_out(char * msg) {
    write(1, msg, strlen(msg));
}


void trace_handler(const char* fmt, const char * file, const char * func, unsigned int line, char * trace_format, ...) {
	va_list ap;
	char debug_buffer[MAX_DEBUG_BUFFER];

    if(func) {
        my_sprintf(debug_buffer, 
            trace_format,
            file,
            func,
            line);
    }
    else {
        my_sprintf(debug_buffer, 
        trace_format,
		file,
		line);

    }

    va_start (ap, fmt);
    my_sprintf(debug_buffer + strlen(debug_buffer),
        fmt,
        ap);
    va_end (ap);
    write_out(debug_buffer);
}
#define TRACE(fmt, ...) trace_handler(fmt, __FILE__, __FUNCTION__ ,__LINE__, TRACE_FORMAT, ##__VA_ARGS__)


void say_hi() {
    write_out("Hi\n");
}

void say_hello() {
    write_out("Hello\n");
}

typedef void (*function_t)();

static const function_t funcs[] = {
    &say_hi,
    &say_hello
};

void test_jump_table(int random) {

    switch(random) {
        case 1:
            write_out("Case is 1\n");
        default:
            write_out("Case is default\n");
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



// This function doesn't get any arguments, the int random is only for the compiler to not optimize the switch case
void main(int random) {
    int status;
    TRACE("Hello from shellcode!\n");
    TRACE("Testing jump tables\n");
    test_jump_table(random);
    TRACE("Testing global ptr arrays\n");
    test_global_ptr_arrays();
    struct elf_information_struct info;
    TRACE("Calling get elf information, testing dynamic shellcode\n");
    if((status=get_elf_information(&info)) == ERROR) {
        TRACE("Error while calling get elf information\n");
        goto error;
    }
    TRACE("get_elf_information status = %x\n", status);

    TRACE("Got elf information: header size = %x, loader size = %x\n", info.elf_header_size, info.loader_size);

error:
    return;
}

