#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void write_out(char * msg) {
    write(1, msg, strlen(msg));
}

void main() {
    write_out("Hello from shellcode!\n");
}

