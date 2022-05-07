_start:
 jmp main

get_pc:
    mov rax, [rsp]
    ret

main:
    push rbp
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    mov rbp, rsp
    ; First thing to do is to find the relocation table
    call get_pc
    ; rax has the address of pc now, we are going to perform
    ; a search for the relocation table magic
    mov rbx, 0xfff ; the depth for our search
    mov rcx, 0x8899aabbccddee00 ; the magic
    ; in x86 the opcode can be 5 bytes long
    ; if we didn't split this load operation the resulting opcode is:
    ; B9 DD CC BB AA 
    ; so we perform this trick to overcome this 
    add rcx, 0xff 

search_for_table:
    add rax, 1 ; x86 opcodes sizes may differ
    mov rdx, [rax]
    cmp rdx, rcx
    je found_table
    jmp search_for_table
    

exit_search:
    jmp exit
found_table:
    ; table address is in rax
    add rax, 8 ; we write quadric word for magic, and we skip it
    
    mov rcx, [rax] ; this is the table size (first entry)
    lea rdx, [rax] ; loading the address of the table to rdx
    add rdx, rcx ; adding the size of the table, now rdx point to shellcode start
    add rdx, 16 ; table is [size][table][entry] we add size + entry
    add rax, 8 ; point to the first table entry (skip table size)
; rax = current table entry
; rcx = table size 
relocate:
    mov rsi, [rax]
    mov rdi, [rax+8]
    add rdi, rdx ; fix the offset
    mov [rsi + rdx], rdi ; fix the offset
    add rax, 16 ; size of 2 qds
    sub rcx, 16
    cmp rcx, 1
    jg relocate

jump_to_main:
    ; rax point to the header which is the entry point
    mov rdi, [rax]
    add rdi, rdx
    ; now rax point to shellcode main
    sub rsp, 32
    xor rax, rax
    mov [rsp], rax ; argc count
    lea rax, [rsp+8]
    mov [rsp+8], rax ; argv ptr  
    call rdi
    add rsp, 32

exit:
    pop rdi 
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    pop rbp
    ret

relocatable_table:
    dq 0x8899aabbccddeeff
