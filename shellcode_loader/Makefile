# the compiler: gcc for C program, define as g++ for C++

# compiler flags:
CFLAGS=-g -Wall -static


# the build target executable:
TARGET = main

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) -o ../outputs/shellcode_loader_$(ARCH).out $(TARGET).c -Os
	$(HOST)strip --strip-debug -o ./shelf_loader/shelf_loader/resources/shellcode_loader_$(ARCH).out ../outputs/shellcode_loader_$(ARCH).out
	$(CC) $(CFLAGS) $(LDFLAGS) -DNO_RWX -o ../outputs/shellcode_loader_no_rwx_$(ARCH).out $(TARGET).c
	$(HOST)strip --strip-debug -o ./shelf_loader/shelf_loader/resources/shellcode_loader_no_rwx_$(ARCH).out ../outputs/shellcode_loader_no_rwx_$(ARCH).out

clean:
	$(RM) $(TARGET)

