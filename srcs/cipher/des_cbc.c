#include "cipher.h"

/*
** TODO: DES in CBC mode (V.0.5). Also serves the "des" alias.
**   Like ECB, but each plaintext block is XOR'd with the previous ciphertext
**   block (the first with the IV from -v) before des_block_crypt; on decrypt,
**   XOR the block output with the previous ciphertext block. The IV advances
**   after every block.
*/
int	des_cbc_command(const t_cipher *self, int argc, char **argv)
{
	(void)self;
	(void)argc;
	(void)argv;
	ft_putstr_fd("ft_ssl: des-cbc: not yet implemented\n", 2);
	return (1);
}
