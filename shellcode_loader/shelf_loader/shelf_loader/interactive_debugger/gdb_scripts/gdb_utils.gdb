define _ms
    x/20i $pc
    si
end

define ms
    python py_ms()
end

define mni
    x/20i $pc
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