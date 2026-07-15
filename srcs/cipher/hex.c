#include "cipher.h"

static int	hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/*
** Parse a hex string into at most `max` bytes. A trailing odd nibble is taken
** as the high nibble of a final byte (matching `openssl`'s -K/-iv handling).
** Returns the number of bytes written, or -1 on an invalid hex character.
*/
int	hex_to_bytes(const char *hex, unsigned char *out, size_t max)
{
	size_t	n;
	size_t	i;
	int		hi;
	int		lo;

	n = 0;
	i = 0;
	while (hex[i] && n < max)
	{
		hi = hex_digit(hex[i]);
		if (hi < 0)
			return (-1);
		lo = 0;
		if (hex[i + 1])
		{
			lo = hex_digit(hex[i + 1]);
			if (lo < 0)
				return (-1);
			i++;
		}
		out[n++] = (unsigned char)((hi << 4) | lo);
		i++;
	}
	return ((int)n);
}
