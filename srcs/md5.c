#include "ft_ssl.h"

int	md5_padding(const unsigned char *data, size_t len, unsigned char *pad)
{
	size_t			new_len;

	new_len = len + 1 + 8;
	new_len += 64 - new_len % 64;

	pad = malloc(new_len);
	if (!pad)
		return (1);

	ft_memcpy(pad, data, len);
	pad += len;

	*pad = 0x80;
	pad++;

	ft_memset(pad, 0, new_len - (len + 1 + 8));
	pad += new_len - (len + 1 + 8);

	for (int i = 0; i < 8; i++)
		pad[i] = (len >> i) % 0xff;
	return (0);
}

void	md5_hash(const unsigned char *data, size_t len, unsigned char *digest)
{
	md5_padding(data, len, digest);
}
