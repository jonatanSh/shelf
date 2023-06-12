define ms
x/20i $pc
    si
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