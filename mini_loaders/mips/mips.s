.globl _start
_start:
    addiu $sp, $sp, -32
    sw $ra, 0($sp)
    sw $a0, 4($sp)
    sw $a1, 8($sp)
    sw $a2, 12($sp)
    sw $a3, 16($sp)
    sw $t8, 20($sp)
    sw $t9, 24($sp)

    la $a0, relocatable_table
    lw $a1, 4 # Current entry start from 4 because the first 4 bytes are the size
    sw $a1, 28($sp)
    lw $a1, 0($a0) # size of relocatable table


relocate:
    la $a0, relocatable_table
    lw $a2, 28($sp)
    add $a0, $a0, $a2

    lw $a2, 0($a0) # This is the file offset
    addiu $a0, $a0, 4
    lw $a3, 0($a0) # This is the virtual offset
    
    # Loading the shellcode
    la $a0, relocatable_table
    
    addu $a3, $a3, $a0 # This is the function offset (base_address+v_offset)
    # Ofsseting with f_offset
    addu $a0, $a0, $a2
    sw $a3, 0($a0) # Correcting the offset

    # End of loop
    lw $a2, 28($sp)
    addu $a2, $a2, 8 # Adavance table pointer by 8 (f_offset, v_offset)
    sw $a2, 28($sp)
    addiu $a1, $a1, -1 # number of entries in the table
    bgez $a1, relocate


    sw $ra, 0($sp)
    sw $a0, 4($sp)
    sw $a1, 8($sp)
    sw $a2, 12($sp)
    sw $a3, 16($sp)
    sw $t8, 20($sp)
    sw $t9, 24($sp)
    addiu $sp, $sp, 32
    jr $ra



relocatable_table:
