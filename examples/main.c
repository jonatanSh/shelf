#include <unistd.h>
#include <stdlib.h>
#include <string.h>



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

static const void * funcs[] = {
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

void test_global_ptr_arrays(int random) {
    if(random == 3) {
        ((function_t)funcs[0])();
    }
    else {
        ((function_t)funcs[1])();
    }
}



// This function doesn't get any arguments, the int random is only for the compiler to not optimize the switch case
void main(int random) {
    write_out("Hello from shellcode!\n");
    write_out("Testing jump tables\n");
    test_jump_table(random);
    write_out("Testing global ptr arrays\n");
    test_global_ptr_arrays(random);
}

