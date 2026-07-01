#include "ft_ssl.h"

void	sha256_hash(const unsigned char *data, size_t len,
			unsigned char *digest)
{
	(void)data;
	(void)len;
	/* TODO: implement SHA-256. Placeholder keeps the digest well-defined. */
	ft_memset(digest, 0, SHA256_DIGEST_LENGTH);
}
