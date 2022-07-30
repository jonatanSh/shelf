#include "./syscalls_wrapper/unistd.h"
#include <stdarg.h>
#include "../debug.h"
#include "../sprintf.h"
#include "../string.h"

void trace_handler(const char * file, const char * func, unsigned int line, char * trace_format, const char* fmt, ...) {
	va_list ap;
	char debug_buffer[MAX_DEBUG_BUFFER];


    my_sprintf(debug_buffer, 
        trace_format,
        file,
        func,
        line);

    va_start (ap, fmt);
    my_vsprintf(debug_buffer + strlen(debug_buffer),
        fmt,
        ap);
    va_end (ap);
    sys_write(1, debug_buffer, strlen(debug_buffer));
    sys_write(1, "\n", 1);

}
