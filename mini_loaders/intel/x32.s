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
    push esi
    push edi

    ; First thing to do is to find the relocation table
    call get_pc
    ; eax has the address of pc now, we are going to perform
    ; a search for the relocation table magic
    mov ebx, 0xfff ; the depth for our search
    mov ecx, 0xaabbcc00 ; the magic
    ; in x86 the opcode can be 5 bytes long
    ; if we didn't split this load operation the resulting opcode is:
    ; B9 DD CC BB AA 
    ; so we perform this trick to overcome this 
    add ecx, 0xdd 

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
    mov ebx, eax ; this point to the table
    add ebx, 4 ; we skip the table size and thats the first entry of the table
    
    mov ecx, [eax] ; this is the table size (first entry)
    lea edx, [eax] ; loading the address of the table to edx
    add edx, ecx ; adding the size of the table, now edx point to shellcode start
    add edx, 8 ; table is [size][table][entry] we add size + entry
    add eax, 4 ; point to the first table entry (skip table size)
; eax = current table entry
; ecx = table size 
relocate:
    mov esi, [eax]
    mov edi, [eax+4]
    add edi, edx ; fix the offset
    mov [esi + edx], edi ; fix the offset
    add eax, 8
    sub ecx, 8
    cmp ecx, 1
    jg relocate

jump_to_main:
    ; eax point to the header which is the entry point
    mov edi, [eax]
    add edi, edx
    ; now eax point to shellcode main
    call edi

exit:
    pop eax
    pop ebx
    pop ecx
    pop edx
    pop esi
    pop edi
    ret

relocatable_table:
    dd 0xaabbccdd
