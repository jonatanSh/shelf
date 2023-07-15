#include <string.h>
#include <signal.h>
void print_out(char * message) {
    write(1, message, strlen(message));
    write(1, "\n", 1);
}
void main() {
    print_out("error should occuer in symbol: my_test_error_function");
    my_test_error_function();
}

void my_test_error_function() {
    /*
        Can't raise here.
        if i raise the seg fault will ocuer inside libc code
    */
    size_t addresses[] = {0x0, (size_t)(-1), 0x123456};
    size_t value = 0xdeadbeffdeadbeff;
    for(size_t i = 0; i < sizeof(addresses) / sizeof(size_t); i++) {
        size_t address = addresses[i];
        *((size_t*)(address)) = value;
    }
    
}