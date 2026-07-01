#include "ft_ssl.h"

/*
** SHA-256 (FIPS 180-4).
**
** Fill `digest` with SHA256_DIGEST_LENGTH (32) bytes computed from the `len`
** bytes at `data`, written in the natural digest order so that put_hex()
** renders the usual sha256sum-compatible hexadecimal string.
**
** Outline of the algorithm to implement here:
**   1. Pad the message: append 0x80, then 0x00 until length % 64 == 56,
**      then append the original bit length as a 64-bit big-endian integer.
**   2. Initialise the eight state words H0..H7.
**   3. For each 64-byte block, build the 64-entry message schedule W and run
**      the 64 compression rounds using the constants K.
**   4. Serialise H0..H7 as big-endian into `digest`.
*/
void	sha256_hash(const unsigned char *data, size_t len,
			unsigned char *digest)
{
	(void)data;
	(void)len;
	/* TODO: implement SHA-256. Placeholder keeps the digest well-defined. */
	ft_memset(digest, 0, SHA256_DIGEST_LENGTH);
}
