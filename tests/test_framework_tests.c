#include <string.h>
void print_out(char * message) {
    write(1, message, strlen(message));
    write(1, "\n", 1);
}
void main() {
    print_out("error should occuer in symbol: my_test_error_function");
    my_test_error_function();
}

void my_test_error_function() {
    int * address = (int*)(0x0);
    print_out("Causing segfault accessing address: *0x0=0xdeadbeff");
    *(address) = 0xdeadbeff;
}