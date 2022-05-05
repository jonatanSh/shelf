_start:
 jmp main

get_pc:
    mov eax, [esp]
    ret

main:
    push ebp
    mov ebp, esp
    sub esp, 8

    leave
    retn