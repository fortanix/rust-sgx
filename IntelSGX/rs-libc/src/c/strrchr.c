#include <string.h>

char *__memrchr(const char *, int, int);

char *strrchr(const char *s, int c)
{
	return __memrchr(s, c, strlen(s) + 1);
}

