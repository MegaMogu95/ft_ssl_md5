#include "ft_ssl.h"
#include "digest.h"
#include "cipher.h"

/*
** Message-digest commands. Adding one is a single new entry plus its
** implementation file.
*/
const t_digest	g_digests[] = {
	{"md5", "MD5", MD5_DIGEST_LENGTH, md5_hash},
	{"sha256", "SHA256", SHA256_DIGEST_LENGTH, sha256_hash},
	{NULL, NULL, 0, NULL}
};

/*
** Cipher commands. "des" is an alias for des-cbc, matching OpenSSL.
*/
const t_cipher	g_ciphers[] = {
	{"base64", base64_command},
	{"des-ecb", des_ecb_command},
	{"des-cbc", des_cbc_command},
	{"des", des_cbc_command},
	{NULL, NULL}
};

/*
** The unified command table: each command names either a digest or a cipher
** descriptor. main() routes on `kind`.
*/
static const t_command	g_commands[] = {
	{"md5", CMD_DIGEST, &g_digests[0]},
	{"sha256", CMD_DIGEST, &g_digests[1]},
	{"base64", CMD_CIPHER, &g_ciphers[0]},
	{"des-ecb", CMD_CIPHER, &g_ciphers[1]},
	{"des-cbc", CMD_CIPHER, &g_ciphers[2]},
	{"des", CMD_CIPHER, &g_ciphers[3]},
	{NULL, CMD_DIGEST, NULL}
};

const t_command	*find_command(const char *cmd)
{
	int	i;

	i = 0;
	while (g_commands[i].cmd)
	{
		if (ft_strcmp(g_commands[i].cmd, cmd) == 0)
			return (&g_commands[i]);
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
** "Commands:" listing shown in the subject.
*/
void	print_invalid_command(const char *cmd)
{
	int	i;

	ft_putstr_fd("ft_ssl: Error: '", 2);
	ft_putstr_fd(cmd, 2);
	ft_putstr_fd("' is an invalid command.\n\nCommands:\n", 2);
	i = 0;
	while (g_commands[i].cmd)
	{
		ft_putstr_fd(g_commands[i].cmd, 2);
		ft_putstr_fd("\n", 2);
		i++;
	}
}
