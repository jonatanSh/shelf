#include "./syscalls_wrapper/unistd.h"
#include <stdarg.h>
#include "../debug.h"
#include "../sprintf.h"
#include "../string.h"

void trace_handler(const char * terminator,const char * file, const char * func, unsigned int line, char * trace_format, const char* fmt, ...) {
	va_list ap;
	char debug_buffer[MAX_DEBUG_BUFFER];
    // Setting the first char as a null terminator
    // This is important
    debug_buffer[0] = 0x0; 


    if(trace_format) {
        my_sprintf(debug_buffer, 
            trace_format,
            file,
            func,
            line);
    }
    
    va_start (ap, fmt);
    my_vsprintf(debug_buffer + strlen(debug_buffer),
        fmt,
        ap);
    va_end (ap);
    sys_write(1, debug_buffer, strlen(debug_buffer));
    if(terminator) {
        sys_write(1, terminator, strlen(terminator));
    }

}
