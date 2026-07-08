#include "cipher.h"

/*
** Entry point for a cipher command. Each cipher owns its argument parsing and
** I/O because their flags differ from the digest commands. argv[0] is the
** command name.
*/
int	run_cipher(const t_cipher *cipher, int argc, char **argv)
{
	return (cipher->run(cipher, argc, argv));
}
