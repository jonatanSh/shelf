define ms
    disassm $pc
    si
end

document ms
    Disassemble and step instruction
end

define mni
    disassm $pc
    nexti
end

document mni
    Disassemble and next instruction
end

define exit
    python api_handler.execute("exit")
end

document exit
    Terminate the current gdb session gracefully and exit
end

define get_stdout
    python api_handler.execute("get_stdout")
end

document get_stdout
    Return shelf loader stdout
end

define execute_shellcode
    python api_handler.execute("execute_shellcode")
end

document execute_shellcode
    Execute the shellcode and break on mini loader entry point
end

define display_shellcode_symbols
    python api_handler.execute("display_shellcode_symbols")
end

document display_shellcode_symbols
    Display symbols declared inside the shellcode this only works if executed with --source-elf
end


define break_on_shellcode_main
    execute_shellcode
    python api_handler.execute("break_on_symbol", 'main')
    mc
    disassm $pc
end

document break_on_shellcode_main
    Execute the shellcode and break on shellcode main, post relocations
end

define disassm
    python api_handler.execute("_disassm", "$pc")
end

document disassm
    Disassemble relative to $pc
end

define shelf_trace
    python api_handler.execute("debug_flow_manager_generate_flow")
end

document shelf_trace
    Execute the shelf trace functions
end

define mc
    python api_handler.execute("my_continue")
end

document mc
    Continue execution
end

define enable_verbose_exceptions
    python api_handler.execute("enable_verbose_exceptions")
end

document enable_verbose_exceptions
    Set verbose exceptions to on
end

define step_to_end
    python api_handler.execute("step_to_end")
end

document step_to_end
    Step until last instruction == current instruction
end

define shellcode_debug
    python api_handler.execute("shellcode_debug")
end


document shellcode_debug
    Add break point on each function of the shellcode the execute it
end