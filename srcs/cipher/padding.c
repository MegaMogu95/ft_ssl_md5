#include "cipher.h"

/*
** PKCS#7 padding, as used by `openssl enc`. `buf` must have room for up to
** `block` extra bytes. When the length is already a multiple of `block`, a
** whole extra block of padding is added so decryption is unambiguous.
** Returns the padded length.
*/
size_t	pad_block(unsigned char *buf, size_t len, size_t block)
{
	size_t	pad;
	size_t	i;

	pad = block - (len % block);
	i = 0;
	while (i < pad)
	{
		buf[len + i] = (unsigned char)pad;
		i++;
	}
	return (len + pad);
}

/*
** Strip PKCS#7 padding. Returns the unpadded length, or the original length
** unchanged if the padding is not well formed (so callers never underflow).
*/
size_t	unpad_block(unsigned char *buf, size_t len)
{
	unsigned char	pad;
	size_t			i;

	if (len == 0)
		return (0);
	pad = buf[len - 1];
	if (pad == 0 || pad > 8 || pad > len)
		return (len);
	i = 0;
	while (i < pad)
	{
		if (buf[len - 1 - i] != pad)
			return (len);
		i++;
	}
	return (len - pad);
}
