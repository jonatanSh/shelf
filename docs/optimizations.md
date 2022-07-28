
# Optimizations
some Compiler optimization (like -o3) may produce un-shellcodeable output.
#### Example of compiler optimization (intel x32):

```c
void * func1() {
    // ... function code
}
void * func2() {
    // ... function code
}

void * funcs[2] = {
    func1,
    func2
};

void main(int argc) {
    if(argc == 1) {
        funcs[0]();    
    }
    else {
        funcs[1]();
    }
}

```
This example actually fools -fPIE and the provided output is

```asm
cmp eax, 1 ; argc
je call_func_zero
; address is incorrect here because we are in PIC mode
call <address_of_func_one> 
call_func_zero:
    call <address_of_func_zero>
```
Address is incorrect and should be calculated as:
```asm
get_pc:
    mov eax, [esp]
    ret

call get_pc
lea eax, [eax+relative_address_of_func_1]
; then
call eax
```
