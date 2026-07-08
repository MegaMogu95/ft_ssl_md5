#include "cipher.h"

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
	ft_putstr_fd("ft_ssl: base64: not yet implemented\n", 2);
	return (1);
}
