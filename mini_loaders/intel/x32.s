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
    mov ebp, esp
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
    
    mov ecx, [eax] ; this is the table size (first entry)
    lea edx, [eax] ; loading the address of the table to edx
    add edx, ecx ; adding the size of the table, now edx point to shellcode start
    add edx, 8 ; table is [size][table][entry] we add size + entry
    add eax, 4 ; point to the first table entry (skip table size)
; eax = current table entry
; ecx = table size 
relocate:
    mov ebx, [eax] ; size
    mov esi, [eax + 4] ; offset in mem
    mov edi, [eax + 8] ; offset to relocate
    add edi, edx ; fix the offset
    mov [esi + edx], edi ; fix the offset
    add eax, ebx
    sub ecx, ebx
    cmp ecx, 1
    jg relocate

jump_to_main:
    ; eax point to the header which is the entry point
    mov edi, [eax]
    add edi, edx
    ; now eax point to shellcode main
    sub esp, 20
    xor eax, eax
    mov [esp], eax ; argc count
    lea eax, [esp+4]
    mov [esp+4], eax ; argv ptr  
    call edi
    add esp, 20

exit:
    pop edi 
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret

relocatable_table:
    dd 0xaabbccdd
