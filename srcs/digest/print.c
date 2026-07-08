#include "digest.h"

/*
** Error printed when a file operand cannot be read, e.g.
**   ft_ssl: md5: nope: No such file or directory
*/
void	print_file_error(t_digest_ctx *ctx, const char *name)
{
	ft_putstr_fd("ft_ssl: ", 2);
	ft_putstr_fd(ctx->digest->cmd, 2);
	ft_putstr_fd(": ", 2);
	ft_putstr_fd(name, 2);
	ft_putstr_fd(": ", 2);
	ft_putstr_fd(strerror(errno), 2);
	ft_putstr_fd("\n", 2);
}

/*
** Echo the STDIN content (used by -p) without its single trailing newline,
** so the quoted form stays on one line while the digest still covers the
** full input including that newline.
*/
static void	write_stdin_echo(t_input *in)
{
	size_t	len;

	len = in->len;
	if (len > 0 && in->data[len - 1] == '\n')
		len--;
	if (len > 0)
		write(1, in->data, len);
}

/*
** Print the quoted operand (the file path, or the string wrapped in double
** quotes as OpenSSL does).
*/
static void	write_operand(t_input *in)
{
	if (in->type == SRC_STRING)
	{
		ft_putstr_fd("\"", 1);
		ft_putstr_fd(in->label, 1);
		ft_putstr_fd("\"", 1);
	}
	else
		ft_putstr_fd(in->label, 1);
}

/*
** STDIN handling. With -p the content is echoed; the layout depends on -q.
** Without -p, plain STDIN prints "(stdin)= <digest>".
*/
static void	print_stdin(t_digest_ctx *ctx, t_input *in, const unsigned char *dg)
{
	size_t	dlen;

	dlen = ctx->digest->digest_len;
	if (ctx->flags & FLAG_P)
	{
		if (ctx->flags & FLAG_Q)
		{
			write_stdin_echo(in);
			ft_putstr_fd("\n", 1);
			put_hex(dg, dlen, 1);
			ft_putstr_fd("\n", 1);
			return ;
		}
		ft_putstr_fd("(\"", 1);
		write_stdin_echo(in);
		ft_putstr_fd("\")= ", 1);
		put_hex(dg, dlen, 1);
		ft_putstr_fd("\n", 1);
		return ;
	}
	if (ctx->flags & (FLAG_Q | FLAG_R))
	{
		put_hex(dg, dlen, 1);
		ft_putstr_fd("\n", 1);
		return ;
	}
	ft_putstr_fd("(stdin)= ", 1);
	put_hex(dg, dlen, 1);
	ft_putstr_fd("\n", 1);
}

/*
** Format the result for one input according to the active flags.
*/
void	print_result(t_digest_ctx *ctx, t_input *in, const unsigned char *dg)
{
	size_t	dlen;

	dlen = ctx->digest->digest_len;
	if (in->type == SRC_STDIN)
		return (print_stdin(ctx, in, dg));
	if (ctx->flags & FLAG_Q)
	{
		put_hex(dg, dlen, 1);
		ft_putstr_fd("\n", 1);
		return ;
	}
	if (ctx->flags & FLAG_R)
	{
		put_hex(dg, dlen, 1);
		ft_putstr_fd(" ", 1);
		write_operand(in);
		ft_putstr_fd("\n", 1);
		return ;
	}
	ft_putstr_fd(ctx->digest->name, 1);
	ft_putstr_fd(" (", 1);
	write_operand(in);
	ft_putstr_fd(") = ", 1);
	put_hex(dg, dlen, 1);
	ft_putstr_fd("\n", 1);
}
