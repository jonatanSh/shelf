#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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



void write_out(char * msg) {
    write(1, msg, strlen(msg));
}

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



// This function doesn't get any arguments, the int random is only for the compiler to not optimize the switch case
void main(int random) {
    write_out("Hello from shellcode!\n");
    write_out("Testing jump tables\n");
    test_jump_table(random);
    write_out("Testing global ptr arrays\n");
    test_global_ptr_arrays();
    struct elf_information_struct info;
    write_out("Hello\n");
    //get_elf_information(&info);
}

