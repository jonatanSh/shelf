# the compiler: gcc for C program, define as g++ for C++
CC=mips-linux-gnu-gcc-10

# compiler flags:
CFLAGS=-g -Wall -static


# the build target executable:
TARGET = main

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) -o ../outputs/shellcode_loader.out $(TARGET).c

clean:
	$(RM) $(TARGET)

