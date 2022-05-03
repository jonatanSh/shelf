#include <unistd.h>
#include <stdlib.h>
#include <string.h>
void main() {
    char * message = "Hello from shellcode !\n";
    write(1, message, strlen(message));
}