#include "ft_ssl.h"

/*
** Hash one input and print its result.
*/
static void	digest_and_print(t_ssl *ssl, t_input *in)
{
	unsigned char	digest[MAX_DIGEST_LENGTH];

	ssl->algo->hash(in->data, in->len, digest);
	print_result(ssl, in, digest);
}

/*
** Read STDIN, hash it and print. Used when -p is set or when no operand was
** given on the command line (the default "read from the console" behavior).
*/
static int	run_stdin(t_ssl *ssl)
{
	t_input	in;

	in.type = SRC_STDIN;
	in.label = NULL;
	in.data = NULL;
	in.len = 0;
	in.next = NULL;
	if (read_fd(0, &in.data, &in.len) != 0)
		return (1);
	digest_and_print(ssl, &in);
	free(in.data);
	return (0);
}

/*
** Process every input: STDIN first (when applicable), then the strings and
** files in command-line order. A file that cannot be read reports an error
** and does not abort the run.
*/
int	run(t_ssl *ssl)
{
	t_input	*in;
	int		status;

	status = 0;
	if ((ssl->flags & FLAG_P) || ssl->inputs == NULL)
		status |= run_stdin(ssl);
	in = ssl->inputs;
	while (in)
	{
		if (in->type == SRC_FILE)
		{
			if (read_file(in->label, &in->data, &in->len) != 0)
			{
				print_file_error(ssl, in->label);
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
		digest_and_print(ssl, in);
		in = in->next;
	}
	return (status);
}
