#ifndef FT_SSL_H
# define FT_SSL_H

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <errno.h>
# include <string.h>
# include <stdint.h>

# define CHUNK_SIZE 64

/*
** A command is either a message-digest command (md5, sha256) or a cipher
** command (base64, des-ecb, des-cbc). `impl` points at the matching
** descriptor: a const t_digest * for digests, a const t_cipher * for ciphers.
*/
typedef enum e_kind
{
	CMD_DIGEST,
	CMD_CIPHER
}	t_kind;

typedef struct s_command
{
	const char	*cmd;
	t_kind		kind;
	const void	*impl;
}	t_command;

/* dispatch.c */
const t_command	*find_command(const char *cmd);
void			print_usage(void);
void			print_invalid_command(const char *cmd);

/* read_file.c -- shared input helpers (read whole fd/file into a buffer) */
int				read_fd(int fd, unsigned char **out, size_t *outlen);
int				read_file(const char *path, unsigned char **out, size_t *outlen);

/* utils.c -- shared libft-style helpers */
size_t			ft_strlen(const char *s);
int				ft_strcmp(const char *a, const char *b);
void			*ft_memcpy(void *dst, const void *src, size_t n);
void			ft_memset(void *ptr, int value, size_t n);
void			ft_putstr_fd(const char *s, int fd);
void			ft_putchar_fd(char c, int fd);
void			put_hex(const unsigned char *bytes, size_t len, int fd);

#endif
