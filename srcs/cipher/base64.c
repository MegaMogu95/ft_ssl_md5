#include "cipher.h"

static uint8_t	base64_encode6b(uint8_t	n)
{
	if (n > 63)
		return ('%');
	else if (n < 26)
		return ('A' + n);
	else if (n < 52)
		return ('a' + n);
	else if (n < 62)
		return ('0' + n);
	else if (n == 62)
		return ('+');
	else
		return ('/');
}

void	base64_encode_chunk(uint8_t dest[4], uint8_t data[3])
{
	uint32_t	n;

	n = data[0] + data[1] * (1 << 8) + data[2] * (1 << 16);
	for (int i = 0; i < 4; i++)
	{
		dest[i] = base64_encode6b(n & 0x3f);
		n >>= 6;
	}
}

/*
** TODO: base64 encode/decode (V.0.1).
**   flags: -e (default) / -d / -i infile / -o outfile
**   - encode: 3 bytes -> 4 chars, '=' padding, newline every 64 chars
**   - decode: skip whitespace, reverse the mapping
** base64_encode / base64_decode are also reused by `des -a`.
*/
int	base64_command(const t_cipher *self, int argc, char **argv)
{
	(void)self;
	(void)argc;
	(void)argv;
	uint8_t dest[4];
	base64_encode_chunk(dest, (uint8_t *)argv[1]);
	write(1, dest, 4);
	write(1, "\n", 1);
	ft_putstr_fd("ft_ssl: base64: not yet implemented\n", 2);
	return (1);
}
