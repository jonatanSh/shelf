# the compiler: gcc for C program, define as g++ for C++

# compiler flags:
CFLAGS=-g -Wall


# the build target executable:
TARGET = main

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) $(LDFLAGS) -o ../outputs/shellcode_loader_$(ARCH).out $(TARGET).c

clean:
	$(RM) $(TARGET)

