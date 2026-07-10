#include "cipher.h"

static uint8_t	base64_encode6b(uint8_t	n)
{
	if (n > 63)
		return ('=');
	else if (n < 26)
		return ('A' + n);
	else if (n < 52)
		return ('a' + n - 26);
	else if (n < 62)
		return ('0' + n - 52);
	else if (n == 62)
		return ('+');
	else
		return ('/');
}

void	base64_encode_chunk(uint8_t dest[4], const uint8_t *data)
{
	uint32_t	n;

	n = data[0] * (1 << 16) + data[1] * (1 << 8) + data[2];
	for (int i = 3; i >= 0; i--)
	{
		dest[i] = base64_encode6b(n & 0x3f);
		n >>= 6;
	}
}

void	base64_encode(uint8_t *dest, const uint8_t *data, size_t len)
{
	uint8_t	data_chunk[3];

	for(size_t i = 0; i < len; i += 3)
	{
		data_chunk[0] = data[i];
		data_chunk[1] = (i + 1 < len ? data[i + 1] : 0);
		data_chunk[2] = (i + 2 < len ? data[i + 2] : 0);
		base64_encode_chunk(dest, data_chunk);
		if (i + 2 > len)
			dest[i + 2] = '=';
		if (i + 1 > len)
			dest[i + 2] = '=';
		
		dest += 4;
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
	size_t	len = ft_strlen(argv[1]);
	if (len % 3)
		len += 3 - len % 3;
	len = len / 3 * 4;
	uint8_t	*dest = malloc(len);
	base64_encode(dest, (uint8_t *)argv[1], ft_strlen(argv[1]));
	write(1, dest, len);
	write(1, "\n", 1);
	ft_putstr_fd("ft_ssl: base64: not yet implemented\n", 2);
	return (1);
}

//74,65,73
//01110100,01100101,01110011 -> 7628147
//011101,000110,010101,110011