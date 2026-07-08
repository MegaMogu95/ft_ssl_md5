#include "ft_ssl.h"
#include "digest.h"
#include "cipher.h"

int	main(int argc, char **argv)
{
	const t_command	*cmd;

	if (argc < 2)
	{
		print_usage();
		return (1);
	}
	cmd = find_command(argv[1]);
	if (!cmd)
	{
		print_invalid_command(argv[1]);
		return (1);
	}
	if (cmd->kind == CMD_DIGEST)
		return (run_digest((const t_digest *)cmd->impl, argc - 1, argv + 1));
	return (run_cipher((const t_cipher *)cmd->impl, argc - 1, argv + 1));
}
