#include "ft_ssl.h"

/*
** Table of supported commands. Dispatch happens by looking a command up here
** and calling its `hash` function pointer -- adding an algorithm is a single
** new entry plus its implementation file, no changes to the command logic.
*/
static const t_algo	g_algos[] = {
	{"md5", "MD5", MD5_DIGEST_LENGTH, md5_hash},
	{"sha256", "SHA256", SHA256_DIGEST_LENGTH, sha256_hash},
	{NULL, NULL, 0, NULL}
};

const t_algo	*find_algo(const char *cmd)
{
	int	i;

	i = 0;
	while (g_algos[i].cmd)
	{
		if (ft_strcmp(g_algos[i].cmd, cmd) == 0)
			return (&g_algos[i]);
		i++;
	}
	return (NULL);
}

void	print_usage(void)
{
	ft_putstr_fd("usage: ft_ssl command [flags] [file/string]\n", 2);
}

/*
** Printed when the first argument is not a known command, mirroring the
** "Commands:" / "Flags:" listing shown in the subject.
*/
void	print_invalid_command(const char *cmd)
{
	int	i;

	ft_putstr_fd("ft_ssl: Error: '", 2);
	ft_putstr_fd(cmd, 2);
	ft_putstr_fd("' is an invalid command.\n\nCommands:\n", 2);
	i = 0;
	while (g_algos[i].cmd)
	{
		ft_putstr_fd(g_algos[i].cmd, 2);
		ft_putstr_fd("\n", 2);
		i++;
	}
	ft_putstr_fd("\nFlags:\n-p -q -r -s\n", 2);
}
