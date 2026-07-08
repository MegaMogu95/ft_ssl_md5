#include "digest.h"

# define READ_CHUNK 4096

/*
** Grow the accumulation buffer to hold at least `needed` bytes. Uses only
** malloc/free (no realloc): allocate a bigger block, copy, free the old one.
*/
static unsigned char	*grow(unsigned char *buf, size_t *cap, size_t needed)
{
	unsigned char	*bigger;
	size_t			ncap;

	ncap = *cap * 2;
	while (ncap < needed)
		ncap *= 2;
	bigger = (unsigned char *)malloc(ncap);
	if (!bigger)
		return (NULL);
	ft_memcpy(bigger, buf, *cap);
	free(buf);
	*cap = ncap;
	return (bigger);
}

/*
** Read the whole content of `fd` into a freshly allocated buffer.
** Returns 0 on success (caller frees *out), -1 on error (errno set by read).
*/
int	read_fd(int fd, unsigned char **out, size_t *outlen)
{
	unsigned char	tmp[READ_CHUNK];
	unsigned char	*buf;
	size_t			cap;
	size_t			len;
	ssize_t			n;

	cap = READ_CHUNK;
	len = 0;
	buf = (unsigned char *)malloc(cap);
	if (!buf)
		return (-1);
	while (1)
	{
		n = read(fd, tmp, READ_CHUNK);
		if (n <= 0)
			break ;
		if (len + (size_t)n > cap)
		{
			buf = grow(buf, &cap, len + (size_t)n);
			if (!buf)
				return (-1);
		}
		ft_memcpy(buf + len, tmp, (size_t)n);
		len += (size_t)n;
	}
	if (n < 0)
		return (free(buf), -1);
	*out = buf;
	*outlen = len;
	return (0);
}

/*
** Open a file and read its full content. Returns 0 on success, -1 on error
** (errno preserved for the caller's error message).
*/
int	read_file(const char *path, unsigned char **out, size_t *outlen)
{
	int	fd;
	int	saved;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (-1);
	if (read_fd(fd, out, outlen) != 0)
	{
		saved = errno;
		close(fd);
		errno = saved;
		return (-1);
	}
	close(fd);
	return (0);
}
