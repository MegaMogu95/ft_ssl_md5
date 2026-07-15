#include "cipher.h"

static void	cipher_error(const char *cmd, const char *msg)
{
	ft_putstr_fd("ft_ssl: ", 2);
	ft_putstr_fd(cmd, 2);
	ft_putstr_fd(": ", 2);
	ft_putstr_fd(msg, 2);
	ft_putstr_fd("\n", 2);
}

static void	file_error(const char *cmd, const char *name)
{
	ft_putstr_fd("ft_ssl: ", 2);
	ft_putstr_fd(cmd, 2);
	ft_putstr_fd(": ", 2);
	ft_putstr_fd(name, 2);
	ft_putstr_fd(": ", 2);
	ft_putstr_fd(strerror(errno), 2);
	ft_putstr_fd("\n", 2);
}

static int	resolve_key(t_cipher_ctx *ctx, const char *cmd)
{
	if (ctx->flags & CFLAG_P)
		return (derive_key(ctx));
	if (!(ctx->flags & CFLAG_K))
	{
		cipher_error(cmd, "no key given, use -k <hex> or -p <password>");
		return (1);
	}
	return (0);
}

static int	load_input(t_cipher_ctx *ctx, const char *cmd,
			unsigned char **data, size_t *len)
{
	if (ctx->infile)
	{
		if (read_file(ctx->infile, data, len) != 0)
			return (file_error(cmd, ctx->infile), 1);
		return (0);
	}
	if (read_fd(0, data, len) != 0)
		return (file_error(cmd, "stdin"), 1);
	return (0);
}

static void	xor_block(unsigned char *dst, const unsigned char *src)
{
	int	j;

	j = 0;
	while (j < 8)
	{
		dst[j] ^= src[j];
		j++;
	}
}

/*
** Encrypt or decrypt a whole buffer in place, block by block. In CBC mode each
** block is chained with the previous ciphertext block (the first with the IV):
** on encrypt the plaintext is XOR'd with `prev` before the cipher and `prev`
** becomes the ciphertext output; on decrypt the cipher output is XOR'd with
** `prev` and `prev` becomes the (saved) ciphertext input. ECB skips chaining.
*/
static void	des_crypt(t_cipher_ctx *ctx, int mode,
			unsigned char *in, size_t inlen)
{
	unsigned char	prev[8];
	unsigned char	saved[8];
	size_t			i;

	ft_memcpy(prev, ctx->iv, 8);
	i = 0;
	while (i < inlen)
	{
		ft_memcpy(saved, in + i, 8);
		if (mode == DES_MODE_CBC && !ctx->decrypt)
			xor_block(in + i, prev);
		des_block_crypt(in + i, in + i, ctx->key, ctx->decrypt);
		if (mode == DES_MODE_CBC && ctx->decrypt)
		{
			xor_block(in + i, prev);
			ft_memcpy(prev, saved, 8);
		}
		else if (mode == DES_MODE_CBC)
			ft_memcpy(prev, in + i, 8);
		i += 8;
	}
}

/*
** Prepare the plaintext (pad) or validate the ciphertext (length check) before
** running des_crypt. Returns the working buffer via out and outlen. Codes match
** des_crypt: 0 ok, 1 malloc, 2 bad length.
*/
static int	transform(t_cipher_ctx *ctx, int mode,
			unsigned char *in, size_t inlen, unsigned char **out, size_t *outlen)
{
	unsigned char	*buf;

	if (!ctx->decrypt)
	{
		buf = malloc(inlen + 8);
		if (!buf)
			return (1);
		ft_memcpy(buf, in, inlen);
		*outlen = pad_block(buf, inlen, 8);
	}
	else
	{
		if (inlen == 0 || inlen % 8 != 0)
			return (2);
		buf = malloc(inlen);
		if (!buf)
			return (1);
		ft_memcpy(buf, in, inlen);
		*outlen = inlen;
	}
	des_crypt(ctx, mode, buf, *outlen);
	if (ctx->decrypt)
		*outlen = unpad_block(buf, *outlen);
	*out = buf;
	return (0);
}

static int	write_output(t_cipher_ctx *ctx, const char *cmd,
			unsigned char *out, size_t outlen)
{
	int	outfd;
	int	ret;

	outfd = 1;
	if (ctx->outfile)
	{
		outfd = open(ctx->outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (outfd < 0)
			return (file_error(cmd, ctx->outfile), 1);
	}
	if ((ctx->flags & CFLAG_A) && !ctx->decrypt)
		ret = base64_encode_fd(outfd, out, outlen);
	else
		ret = write_all(outfd, out, outlen);
	if (outfd != 1)
		close(outfd);
	return (ret);
}

int	des_run(t_cipher_ctx *ctx, int mode, const char *cmd)
{
	unsigned char	*in;
	unsigned char	*out;
	size_t			inlen;
	size_t			outlen;
	int				ret;

	if (resolve_key(ctx, cmd) || load_input(ctx, cmd, &in, &inlen))
		return (1);
	if ((ctx->flags & CFLAG_A) && ctx->decrypt)
	{
		ret = base64_decode((const char *)in, inlen, &out, &outlen);
		free(in);
		if (ret)
			return (cipher_error(cmd, "invalid base64 input"), 1);
		in = out;
		inlen = outlen;
	}
	ret = transform(ctx, mode, in, inlen, &out, &outlen);
	free(in);
	if (ret == 2)
		return (cipher_error(cmd, "bad input length (not a multiple of 8)"), 1);
	if (ret)
		return (1);
	ret = write_output(ctx, cmd, out, outlen);
	free(out);
	return (ret);
}
