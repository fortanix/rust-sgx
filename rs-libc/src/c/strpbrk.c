#include <stddef.h>

size_t strcspn(const char *s, const char *c);

char *strpbrk(const char *s, const char *b)
{
	s += strcspn(s, b);
	return *s ? (char *)s : 0;
}
