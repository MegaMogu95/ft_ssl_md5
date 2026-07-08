#include "digest.h"

/*
** Append a new input (string or file) to the tail of the list so that the
** processing order matches the command-line order.
*/
t_input	*append_input(t_digest_ctx *ctx, t_src type, char *label)
{
	t_input	*node;

	node = (t_input *)malloc(sizeof(t_input));
	if (!node)
		return (NULL);
	node->type = type;
	node->label = label;
	node->data = NULL;
	node->len = 0;
	node->next = NULL;
	if (ctx->inputs_tail)
		ctx->inputs_tail->next = node;
	else
		ctx->inputs = node;
	ctx->inputs_tail = node;
	return (node);
}

void	free_inputs(t_digest_ctx *ctx)
{
	t_input	*node;
	t_input	*next;

	node = ctx->inputs;
	while (node)
	{
		next = node->next;
		if (node->type == SRC_FILE)
			free(node->data);
		free(node);
		node = next;
	}
	ctx->inputs = NULL;
	ctx->inputs_tail = NULL;
}

/*
** Consume the argument of a -s flag: either the rest of the current token
** (e.g. -sfoo) or the following argv element (e.g. -s foo). Returns the index
** of the last argv element consumed.
*/
static int	take_string_arg(t_digest_ctx *ctx, int i, int argc, char **argv)
{
	char	*token;
	int		pos;

	token = argv[i];
	pos = 0;
	while (token[pos] && token[pos] != 's')
		pos++;
	if (token[pos + 1])
	{
		append_input(ctx, SRC_STRING, &token[pos + 1]);
		return (i);
	}
	if (i + 1 < argc)
	{
		append_input(ctx, SRC_STRING, argv[i + 1]);
		return (i + 1);
	}
	ft_putstr_fd("ft_ssl: ", 2);
	ft_putstr_fd(ctx->digest->cmd, 2);
	ft_putstr_fd(": option requires an argument -- 's'\n", 2);
	return (i);
}

/*
** Parse one option token (e.g. "-pqr" or "-s"). Returns the index of the last
** argv element consumed (may advance past a -s argument).
*/
static int	parse_flags(t_digest_ctx *ctx, int i, int argc, char **argv)
{
	char	*token;
	int		j;

	token = argv[i];
	j = 1;
	while (token[j])
	{
		if (token[j] == 'p')
			ctx->flags |= FLAG_P;
		else if (token[j] == 'q')
			ctx->flags |= FLAG_Q;
		else if (token[j] == 'r')
			ctx->flags |= FLAG_R;
		else if (token[j] == 's')
		{
			ctx->flags |= FLAG_S;
			return (take_string_arg(ctx, i, argc, argv));
		}
		else
		{
			ft_putstr_fd("ft_ssl: ", 2);
			ft_putstr_fd(ctx->digest->cmd, 2);
			ft_putstr_fd(": illegal option\n", 2);
		}
		j++;
	}
	return (i);
}

/*
** Flags are only recognised until the first operand (file/string) is seen;
** everything after it is treated as a file name -- matching OpenSSL's behavior
** where e.g. "md5 file -s" opens a file literally named "-s".
*/
void	parse_args(t_digest_ctx *ctx, int argc, char **argv)
{
	int	i;
	int	opts_done;

	i = 0;
	opts_done = 0;
	while (i < argc)
	{
		if (!opts_done && argv[i][0] == '-' && argv[i][1] != '\0')
			i = parse_flags(ctx, i, argc, argv);
		else
		{
			opts_done = 1;
			append_input(ctx, SRC_FILE, argv[i]);
		}
		i++;
	}
}
