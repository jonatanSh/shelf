#ifndef SPRINTF_HEADER
#define SPRINTF_HEADER

int sprintf(char * buf, const char * fmt, ...);
int vsprintf(char * buf, const char * fmt, va_list va);
#endif