_start:
 jmp main

get_pc:
    mov eax, [esp]
    ret

main:
    push ebp
    push eax
    push ebx
    push ecx
    push edx

    mov ebp, esp
    sub esp, 4

    ; First thing to do is to find the relocation table
    call get_pc
    ; eax has the address of pc now, we are going to perform
    ; a search for the relocation table magic
    mov ebx, 0xfff ; the depth for our search
    mov ecx, 0xaabbccdd ; the magic

search_for_table:
    add eax, 1 ; x86 opcodes sizes may differ
    mov edx, [eax]
    cmp edx, ecx
    je found_table
    jmp search_for_table
    

exit_search:
    jmp exit
found_table:
    ; table address is in eax
    add eax, 4 ; we write double word for magic, and we skip it
    mov [esp], eax ; we save the address of the table
    mov ecx, [eax] ; this is the table size
    
    
    mov ebx, eax ; this point to the table
    add ebx, 4 ; we skip the table size and thats the first entry of the table



exit:
    mov esp, ebp
    pop eax
    pop ebx
    pop ecx
    pop edx
    ret

relocatable_table:
    dd 0xaabbccdd
