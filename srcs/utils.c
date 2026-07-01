#include "ft_ssl.h"

size_t	ft_strlen(const char *s)
{
	size_t	i;

	i = 0;
	while (s[i])
		i++;
	return (i);
}

int	ft_strcmp(const char *a, const char *b)
{
	while (*a && *a == *b)
	{
		a++;
		b++;
	}
	return ((unsigned char)*a - (unsigned char)*b);
}

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	unsigned char		*d;
	const unsigned char	*s;

	d = (unsigned char *)dst;
	s = (const unsigned char *)src;
	while (n--)
		*d++ = *s++;
	return (dst);
}

void	ft_memset(void *ptr, int value, size_t n)
{
	unsigned char	*p;

	p = (unsigned char *)ptr;
	while (n--)
		*p++ = (unsigned char)value;
}

void	ft_putchar_fd(char c, int fd)
{
	write(fd, &c, 1);
}

void	ft_putstr_fd(const char *s, int fd)
{
	if (!s)
		return ;
	write(fd, s, ft_strlen(s));
}

/*
** Write `len` bytes as a lowercase hexadecimal string.
*/
void	put_hex(const unsigned char *bytes, size_t len, int fd)
{
	const char	*hex = "0123456789abcdef";
	char		out[2];
	size_t		i;

	i = 0;
	while (i < len)
	{
		out[0] = hex[(bytes[i] >> 4) & 0xf];
		out[1] = hex[bytes[i] & 0xf];
		write(fd, out, 2);
		i++;
	}
}
