#ifndef DIGEST_H
# define DIGEST_H

# include "ft_ssl.h"

# define MD5_DIGEST_LENGTH 16
# define SHA256_DIGEST_LENGTH 32
# define MAX_DIGEST_LENGTH 64

/*
** Command line flag bits (digest commands).
**   -p : echo STDIN to STDOUT and append the checksum
**   -q : quiet mode (print only the digest)
**   -r : reverse the format of the output
**   -s : print the sum of the given string
*/
# define FLAG_P 1
# define FLAG_Q 2
# define FLAG_R 4
# define FLAG_S 8

typedef enum e_src
{
	SRC_STDIN,
	SRC_STRING,
	SRC_FILE
}	t_src;

typedef struct s_input
{
	t_src			type;
	char			*label;
	unsigned char	*data;
	size_t			len;
	struct s_input	*next;
}	t_input;

typedef struct s_digest
{
	const char	*cmd;
	const char	*name;
	size_t		digest_len;
	void		(*hash)(const unsigned char *data, size_t len,
					unsigned char *digest);
}	t_digest;

/*
** Runtime context for a single digest invocation.
*/
typedef struct s_digest_ctx
{
	const t_digest	*digest;
	int				flags;
	t_input			*inputs;
	t_input			*inputs_tail;
}	t_digest_ctx;

/* run_digest.c */
int				run_digest(const t_digest *digest, int argc, char **argv);

/* parse_digest.c */
void			parse_args(t_digest_ctx *ctx, int argc, char **argv);
t_input			*append_input(t_digest_ctx *ctx, t_src type, char *label);
void			free_inputs(t_digest_ctx *ctx);

/* input.c */
int				read_fd(int fd, unsigned char **out, size_t *outlen);
int				read_file(const char *path, unsigned char **out, size_t *outlen);

/* print.c */
void			print_result(t_digest_ctx *ctx, t_input *in, const unsigned char *dg);
void			print_file_error(t_digest_ctx *ctx, const char *name);

/* md5.c */
void			md5_hash(const unsigned char *data, size_t len,
					unsigned char *digest);

/* sha256.c */
void			sha256_hash(const unsigned char *data, size_t len,
					unsigned char *digest);

extern const t_digest	g_digests[];

#endif
