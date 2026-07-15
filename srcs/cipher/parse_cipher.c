#include "cipher.h"

static void	invalid_option(const char *arg)
{
	ft_putstr_fd("ft_ssl: invalid cipher option '", 2);
	ft_putstr_fd(arg, 2);
	ft_putstr_fd("'\n", 2);
}

/*
** Read a hex operand into `dst` (at most `max` bytes). Returns 0 on success,
** 1 on an invalid hex string.
*/
static int	take_hex(const char *hex, unsigned char *dst, size_t max)
{
	if (hex_to_bytes(hex, dst, max) < 0)
	{
		ft_putstr_fd("ft_ssl: invalid hex value '", 2);
		ft_putstr_fd(hex, 2);
		ft_putstr_fd("'\n", 2);
		return (1);
	}
	return (0);
}

/*
** Handle the flags that consume the next argv token. Returns 1 if `argv[i]`
** was such a flag (advancing *i), 0 if not, and sets *err on a bad value.
*/
static int	parse_valued(t_cipher_ctx *ctx, char **argv, int *i, int *err)
{
	if (!ft_strcmp(argv[*i], "-i"))
		ctx->infile = argv[++(*i)];
	else if (!ft_strcmp(argv[*i], "-o"))
		ctx->outfile = argv[++(*i)];
	else if (!ft_strcmp(argv[*i], "-p"))
	{
		ctx->password = argv[++(*i)];
		ctx->flags |= CFLAG_P;
	}
	else if (!ft_strcmp(argv[*i], "-k"))
	{
		*err = take_hex(argv[++(*i)], ctx->key, DES_KEY_SIZE);
		ctx->flags |= CFLAG_K;
	}
	else if (!ft_strcmp(argv[*i], "-s"))
	{
		*err = take_hex(argv[++(*i)], ctx->salt, 8);
		ctx->flags |= CFLAG_S;
	}
	else if (!ft_strcmp(argv[*i], "-v"))
	{
		*err = take_hex(argv[++(*i)], ctx->iv, DES_BLOCK_SIZE);
		ctx->flags |= CFLAG_V;
	}
	else
		return (0);
	return (1);
}

/*
** Parse the shared cipher flags (-a -d -e -i -o -k -p -s -v) into `ctx`.
** argv[0] is the command name. Returns 0 on success, 1 on any error.
*/
int	parse_cipher_args(t_cipher_ctx *ctx, int argc, char **argv)
{
	int	i;
	int	err;

	i = 1;
	while (i < argc)
	{
		err = 0;
		if (!ft_strcmp(argv[i], "-a"))
			ctx->flags |= CFLAG_A;
		else if (!ft_strcmp(argv[i], "-d"))
			ctx->decrypt = 1;
		else if (!ft_strcmp(argv[i], "-e"))
			ctx->decrypt = 0;
		else if (i + 1 < argc && parse_valued(ctx, argv, &i, &err))
		{
			if (err)
				return (1);
		}
		else
			return (invalid_option(argv[i]), 1);
		i++;
	}
	return (0);
}
