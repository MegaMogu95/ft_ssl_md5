#include "ft_ssl.h"

/*
** MD5 (RFC 1321).
**
** Fill `digest` with MD5_DIGEST_LENGTH (16) bytes computed from the `len`
** bytes at `data`. The bytes must be written in the natural digest order so
** that put_hex() renders the usual md5sum-compatible hexadecimal string.
**
** Outline of the algorithm to implement here:
**   1. Pad the message: append 0x80, then 0x00 until length % 64 == 56,
**      then append the original bit length as a 64-bit little-endian integer.
**   2. Initialise the four state words A, B, C, D.
**   3. For each 64-byte block, run the 64 operations over the four rounds
**      (using the per-step constants K and rotation amounts S).
**   4. Serialise A, B, C, D as little-endian into `digest`.
*/
void	md5_hash(const unsigned char *data, size_t len, unsigned char *digest)
{
	(void)data;
	(void)len;
	/* TODO: implement MD5. Placeholder keeps the digest well-defined. */
	ft_memset(digest, 0, MD5_DIGEST_LENGTH);
}
