#include "cipher.h"

/*
** DES in CBC mode, also serving the bare "des" alias. Shares the whole pipeline
** with des-ecb via des_run(); the CBC chaining lives in des_run.c.
*/
int	des_cbc_command(const t_cipher *self, int argc, char **argv)
{
	t_cipher_ctx	ctx;

	(void)self;
	ft_memset(&ctx, 0, sizeof(ctx));
	if (parse_cipher_args(&ctx, argc, argv))
		return (1);
	return (des_run(&ctx, DES_MODE_CBC, "des-cbc"));
}
