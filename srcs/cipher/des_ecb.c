#include "cipher.h"

/*
** DES in ECB mode. All the real work (argument parsing, key derivation, I/O,
** block processing) is shared with des-cbc through des_run(); only the chaining
** mode differs.
*/
int	des_ecb_command(const t_cipher *self, int argc, char **argv)
{
	t_cipher_ctx	ctx;

	(void)self;
	ft_memset(&ctx, 0, sizeof(ctx));
	if (parse_cipher_args(&ctx, argc, argv))
		return (1);
	return (des_run(&ctx, DES_MODE_ECB, "des-ecb"));
}
