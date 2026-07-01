#include "ft_ssl.h"

int	main(int argc, char **argv)
{
	t_ssl	ssl;
	int		status;

	if (argc < 2)
	{
		print_usage();
		return (1);
	}
	ssl.algo = find_algo(argv[1]);
	if (!ssl.algo)
	{
		print_invalid_command(argv[1]);
		return (1);
	}
	ssl.flags = 0;
	ssl.inputs = NULL;
	ssl.inputs_tail = NULL;
	parse_args(&ssl, argc - 2, argv + 2);
	status = run(&ssl);
	free_inputs(&ssl);
	return (status);
}
