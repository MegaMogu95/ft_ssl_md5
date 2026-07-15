#include "cipher.h"
#include "digest.h"

/*
** Derive the DES key and IV from a password with an MD5-based KDF:
**   key || iv = MD5(password || salt)
** MD5 yields 16 bytes, which is exactly one 8-byte key plus one 8-byte IV.
** An explicit -k key or -v IV always wins over the derived value, mirroring
** how `openssl enc` lets -K/-iv override the password derivation.
*/
int	derive_key(t_cipher_ctx *ctx)
{
	unsigned char	buf[256];
	unsigned char	digest[MD5_DIGEST_LENGTH];
	size_t			plen;

	if (!ctx->password)
		return (0);
	plen = ft_strlen(ctx->password);
	if (plen > sizeof(buf) - 8)
		plen = sizeof(buf) - 8;
	ft_memcpy(buf, ctx->password, plen);
	ft_memcpy(buf + plen, ctx->salt, 8);
	md5_hash(buf, plen + 8, digest);
	if (!(ctx->flags & CFLAG_K))
		ft_memcpy(ctx->key, digest, DES_KEY_SIZE);
	if (!(ctx->flags & CFLAG_V))
		ft_memcpy(ctx->iv, digest + DES_KEY_SIZE, DES_BLOCK_SIZE);
	return (0);
}
