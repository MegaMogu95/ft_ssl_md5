#include "digest.h"

/*
** Hash one input and print its result.
*/
static void	digest_and_print(t_digest_ctx *ctx, t_input *in)
{
	unsigned char	digest[MAX_DIGEST_LENGTH];

	ctx->digest->hash(in->data, in->len, digest);
	print_result(ctx, in, digest);
}

/*
** Read STDIN, hash it and print. Used when -p is set or when no operand was
** given on the command line (the default "read from the console" behavior).
*/
static int	run_stdin(t_digest_ctx *ctx)
{
	t_input	in;

	in.type = SRC_STDIN;
	in.label = NULL;
	in.data = NULL;
	in.len = 0;
	in.next = NULL;
	if (read_fd(0, &in.data, &in.len) != 0)
		return (1);
	digest_and_print(ctx, &in);
	free(in.data);
	return (0);
}

/*
** Process every input: STDIN first (when applicable), then the strings and
** files in command-line order. A file that cannot be read reports an error
** and does not abort the run.
*/
static int	run_all(t_digest_ctx *ctx)
{
	t_input	*in;
	int		status;

	status = 0;
	if ((ctx->flags & FLAG_P) || ctx->inputs == NULL)
		status |= run_stdin(ctx);
	in = ctx->inputs;
	while (in)
	{
		if (in->type == SRC_FILE)
		{
			if (read_file(in->label, &in->data, &in->len) != 0)
			{
				print_file_error(ctx, in->label);
				status = 1;
				in = in->next;
				continue ;
			}
		}
		else
		{
			in->data = (unsigned char *)in->label;
			in->len = ft_strlen(in->label);
		}
		digest_and_print(ctx, in);
		in = in->next;
	}
	return (status);
}

/*
** Entry point for a digest command (md5, sha256). argv[0] is the command
** name; the rest are flags and operands.
*/
int	run_digest(const t_digest *digest, int argc, char **argv)
{
	t_digest_ctx	ctx;
	int				status;

	ctx.digest = digest;
	ctx.flags = 0;
	ctx.inputs = NULL;
	ctx.inputs_tail = NULL;
	parse_args(&ctx, argc - 1, argv + 1);
	status = run_all(&ctx);
	free_inputs(&ctx);
	return (status);
}
