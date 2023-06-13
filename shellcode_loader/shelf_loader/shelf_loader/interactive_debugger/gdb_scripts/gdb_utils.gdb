define ms
    disassm
    si
end

define mni
    disassm
    nexti
end

define exit
    detach
    quit
end

define get_stdout
    python get_stdout()
end

define execute_shellcode
    python execute_shellcode()
end

define display_shellcode_symbols
    python display_shellcode_symbols()
end

define break_on_shellcode_main
    execute_shellcode
    python break_on_symbol('main')
    c
    disassm
end

define disassm
    python disassm()
end