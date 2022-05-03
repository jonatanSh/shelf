.globl _start

_start:
 b main

get_pc:
    move $a0, $ra
    jr $ra

main:
    addiu $sp, $sp, -40
    sw $ra, 0($sp)
    sw $a0, 4($sp)
    sw $a1, 8($sp)
    sw $a2, 12($sp)
    sw $a3, 16($sp)
    sw $t8, 20($sp)
    sw $t9, 24($sp)

    # The first thing we are going to do is to search for the relocatable table
    bal get_pc
    la $a1, 0xffff # The depth for the search
locate_table:
    addiu $a0, $a0, 4 # Pointer to the code
    lw $a2, 0($a0)
    la $a3, 0xaabbccdd # Magic
    beq $a2, $a3, found_table

    addiu $a1, $a1, -4 # Each opcode in mips is 4 bytes
    bgez $a1, locate_table

table_not_found:    
    b exit # Table not found

found_table:
    addiu $a0, $a0, 4 # Address of table without magic

    sw $a0, 36($sp)
    addiu $a1, $a0, 4 # Current entry start from 4 because the first 4 bytes are the size
    sw $a1, 28($sp) # First entry in table
    lw $a1, 0($a0) # size of relocatable table
    # total shellcode header size is size of table + table + entry_point
    addiu $a2, $a0, 8

    move $a3, $a1

    # The table size is (num_of_ptr * 8) + 4 + 4 for size and for entry point
    li $t8, 8
    mult $a3, $t8
    mflo $a3
    addiu $a3, 8

    add $a2, $a2, $a3

    sw $a2, 32($sp)



    # Loading the base address
    lw $t8, 32($sp) # T8 points to the base address

relocate:
    lw $a0, 28($sp)

    lw $a2, 0($a0) # This is the virtual address (f_offset)
    lw $a3, 4($a0) # This is the virtual offset
    
    
    addu $a3, $a3, $t8 # This is the function offset (base_address+v_offset)
    # Ofsseting with f_offset
    addu $a2, $a2, $t8
    sw $a3, 0($a2) # Correcting the offset

    # End of loop
    lw $a2, 28($sp)
    addu $a2, $a2, 8 # Adavance table pointer by 8 (f_offset, v_offset)
    sw $a2, 28($sp)
    addiu $a1, $a1, -1 # number of entries in the table
    bgez $a1, relocate

jump_to_main:
    lw $a0, 36($sp)
    # Here a2 is the offset of main
    # offset of main
    lw $t9, 0($a2)
    # adding base address to offset
    addu $t9, $t9, $t8
    addiu $sp, -0x20 # Stack frame for possible libc start.s
    sw $zero, 0($sp) # argc
    addiu $s3, $sp, 4 # argv
    sw $s3, 4($sp) # argv
    jalr $t9
    nop
    addiu $sp, 0x20

exit:
    sw $ra, 0($sp)
    sw $a0, 4($sp)
    sw $a1, 8($sp)
    sw $a2, 12($sp)
    sw $a3, 16($sp)
    sw $t8, 20($sp)
    sw $t9, 24($sp)
    addiu $sp, $sp, 40
    jr $ra



relocatable_table:
    .WORD 0xaabbccdd
