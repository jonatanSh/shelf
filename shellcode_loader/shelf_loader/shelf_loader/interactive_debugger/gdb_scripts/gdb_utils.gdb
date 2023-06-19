define ms
    disassm $pc
    si
end

define mni
    disassm $pc
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
    disassm $pc
end

define disassm
    python _disassm("$arg0")
end

define shelf_trace
    python debug_flow_manager_generate_flow()
end