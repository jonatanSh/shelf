#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/*
    This is the simplest example for more complex examples take a look under tests
    The test files use many features of the library,
    And provide great examples on how to convert files into shellcodes
*/

void write_out(char * msg) {
    write(1, msg, strlen(msg));
}

void main() {
    write_out("Hello from shellcode!\n");
}

