#include "cipher.h"

/*
** TODO: DES in ECB mode (V.0.4).
**   1. parse_cipher_args -> key (-k hex) or password (-p -> derive_key)
**   2. read input (-i or stdin), base64-decode first if -d && -a
**   3. encrypt: pad_block, then des_block_crypt per 8-byte block
**      decrypt: des_block_crypt per block, then unpad_block
**   4. base64-encode if -e && -a, write to -o or stdout
*/
int	des_ecb_command(const t_cipher *self, int argc, char **argv)
{
	(void)self;
	(void)argc;
	(void)argv;
	ft_putstr_fd("ft_ssl: des-ecb: not yet implemented\n", 2);
	return (1);
}
