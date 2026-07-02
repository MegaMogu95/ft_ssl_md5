#ifndef FT_SSL_H
# define FT_SSL_H

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <errno.h>
# include <string.h>
# include <stdint.h>

# define MD5_DIGEST_LENGTH 16
# define SHA256_DIGEST_LENGTH 32
# define MAX_DIGEST_LENGTH 64
# define CHUNK_SIZE 64

/*
** Command line flag bits.
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

typedef struct s_algo
{
	const char	*cmd;
	const char	*name;
	size_t		digest_len;
	void		(*hash)(const unsigned char *data, size_t len,
					unsigned char *digest);
}	t_algo;

/*
** Runtime context for a single ft_ssl invocation.
*/
typedef struct s_ssl
{
	const t_algo	*algo;
	int				flags;
	t_input			*inputs;
	t_input			*inputs_tail;
}	t_ssl;

/* dispatch.c */
const t_algo	*find_algo(const char *cmd);
void			print_usage(void);
void			print_invalid_command(const char *cmd);

/* parse.c */
void			parse_args(t_ssl *ssl, int argc, char **argv);
t_input			*append_input(t_ssl *ssl, t_src type, char *label);
void			free_inputs(t_ssl *ssl);

/* input.c */
int				read_fd(int fd, unsigned char **out, size_t *outlen);
int				read_file(const char *path, unsigned char **out, size_t *outlen);

/* run.c */
int				run(t_ssl *ssl);

/* print.c */
void			print_result(t_ssl *ssl, t_input *in, const unsigned char *dg);
void			print_file_error(t_ssl *ssl, const char *name);

/* utils.c */
size_t			ft_strlen(const char *s);
int				ft_strcmp(const char *a, const char *b);
void			*ft_memcpy(void *dst, const void *src, size_t n);
void			ft_memset(void *ptr, int value, size_t n);
void			ft_putstr_fd(const char *s, int fd);
void			ft_putchar_fd(char c, int fd);
void			put_hex(const unsigned char *bytes, size_t len, int fd);

/* md5.c */
void			md5_hash(const unsigned char *data, size_t len,
					unsigned char *digest);

/* sha256.c */
void			sha256_hash(const unsigned char *data, size_t len,
					unsigned char *digest);

#endif
