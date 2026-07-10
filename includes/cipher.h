#ifndef CIPHER_H
# define CIPHER_H

# include "ft_ssl.h"

# define DES_BLOCK_SIZE 8
# define DES_KEY_SIZE 8

/*
** Cipher command line flags.
**   -a : base64 the input/output around the cipher
**   -d : decrypt mode        -e : encrypt mode (default)
**   -i : input file          -o : output file
**   -k : key (hex)           -p : password (ascii)
**   -s : salt (hex)          -v : initialization vector (hex)
*/
# define CFLAG_A 0x01
# define CFLAG_D 0x02
# define CFLAG_E 0x04
# define CFLAG_I 0x08
# define CFLAG_O 0x10
# define CFLAG_K 0x20
# define CFLAG_P 0x40
# define CFLAG_S 0x80
# define CFLAG_V 0x100

/*
** Everything a cipher run needs, gathered from the command line and/or
** derived (via pbkdf) from a password.
*/
typedef struct s_cipher_ctx
{
	int				flags;
	char			*infile;
	char			*outfile;
	char			*password;
	unsigned char	key[DES_KEY_SIZE];
	unsigned char	iv[DES_BLOCK_SIZE];
	unsigned char	salt[8];
	int				decrypt;
}	t_cipher_ctx;

typedef struct s_cipher
{
	const char	*cmd;
	int			(*run)(const struct s_cipher *self, int argc, char **argv);
}	t_cipher;

/* run_cipher.c */
int				run_cipher(const t_cipher *cipher, int argc, char **argv);

/* parse_cipher.c */
int				parse_cipher_args(t_cipher_ctx *ctx, int argc, char **argv);

/* base64.c */
int				base64_command(const t_cipher *self, int argc, char **argv);
void			base64_encode(uint8_t *dest, const uint8_t *data, size_t len);
int				base64_decode(const char *in, size_t len,
					unsigned char **out, size_t *outlen);

/* hex.c */
int				hex_to_bytes(const char *hex, unsigned char *out, size_t max);

/* padding.c */
size_t			pad_block(unsigned char *buf, size_t len, size_t block);
size_t			unpad_block(unsigned char *buf, size_t len);

/* pbkdf.c */
int				derive_key(t_cipher_ctx *ctx);

/* des_core.c */
void			des_block_crypt(const unsigned char in[8],
					unsigned char out[8], const unsigned char key[8],
					int decrypt);

/* des_ecb.c / des_cbc.c */
int				des_ecb_command(const t_cipher *self, int argc, char **argv);
int				des_cbc_command(const t_cipher *self, int argc, char **argv);

extern const t_cipher	g_ciphers[];

#endif
