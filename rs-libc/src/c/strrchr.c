#include <stddef.h>

char *__memrchr(const char *, int, int);
size_t strlen(const char *s);

char *strrchr(const char *s, int c)
{
	return __memrchr(s, c, strlen(s) + 1);
}

