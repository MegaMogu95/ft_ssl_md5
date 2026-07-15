#include "cipher.h"

/* Output is wrapped at this many characters per line, like `openssl base64`. */
# define B64_WRAP 64

/*
** Options gathered from the base64 command line. Only used inside this file.
*/
typedef struct s_b64_opts
{
	int		decode;
	char	*infile;
	char	*outfile;
}	t_b64_opts;

/* ------------------------------------------------------------------ encode */

static uint8_t	base64_encode6b(uint8_t n)
{
	if (n < 26)
		return ('A' + n);
	else if (n < 52)
		return ('a' + n - 26);
	else if (n < 62)
		return ('0' + n - 52);
	else if (n == 62)
		return ('+');
	else
		return ('/');
}

static void	base64_encode_chunk(uint8_t dest[4], const uint8_t *data, size_t len)
{
	uint32_t	n;

	n = (uint32_t)data[0] << 16;
	if (len > 1)
		n += (uint32_t)data[1] << 8;
	if (len > 2)
		n += data[2];
	for (size_t i = 0; i < 4; i++)
	{
		if (3 - i < len + 1)
			dest[3 - i] = base64_encode6b(n & 0x3f);
		else
			dest[3 - i] = '=';
		n >>= 6;
	}
}

void	base64_encode(uint8_t *dest, const uint8_t *data, size_t len)
{
	for (size_t i = 0; 3 * i < len; i++)
		base64_encode_chunk(dest + 4 * i, data + 3 * i, len - 3 * i);
}

/* ------------------------------------------------------------------ decode */

static int	base64_decode6b(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	if (c == '+')
		return (62);
	if (c == '/')
		return (63);
	return (-1);
}

static int	is_b64_space(unsigned char c)
{
	return (c == ' ' || c == '\n' || c == '\r'
		|| c == '\t' || c == '\v' || c == '\f');
}

/*
** Streaming decode: collect 6-bit values into an accumulator and emit a byte
** whenever 8 bits are available. Whitespace is skipped, '=' ends the data, and
** any invalid character is an error. The trailing (< 8) bits are padding and
** are discarded, which naturally yields 1 byte for a 2-char tail and 2 bytes
** for a 3-char tail.
*/
int	base64_decode(const char *in, size_t len, unsigned char **out, size_t *outlen)
{
	unsigned char	*buf;
	size_t			o;
	uint32_t		acc;
	int				nbits;

	buf = malloc(len / 4 * 3 + 3);
	if (!buf)
		return (1);
	acc = 0;
	nbits = 0;
	o = 0;
	for (size_t i = 0; i < len; i++)
	{
		unsigned char	c = (unsigned char)in[i];
		int				v;

		if (c == '=')
			break ;
		if (is_b64_space(c))
			continue ;
		v = base64_decode6b(c);
		if (v < 0)
			return (free(buf), 1);
		acc = (acc << 6) | (uint32_t)v;
		nbits += 6;
		if (nbits >= 8)
		{
			nbits -= 8;
			buf[o++] = (acc >> nbits) & 0xff;
		}
	}
	*out = buf;
	*outlen = o;
	return (0);
}

/* -------------------------------------------------------------------- i/o */

int	write_all(int fd, const void *buf, size_t len)
{
	size_t	off;
	ssize_t	n;

	off = 0;
	while (off < len)
	{
		n = write(fd, (const char *)buf + off, len - off);
		if (n < 0)
			return (1);
		off += (size_t)n;
	}
	return (0);
}

static int	write_wrapped(int fd, const unsigned char *buf, size_t len)
{
	size_t	off;
	size_t	chunk;

	off = 0;
	while (off < len)
	{
		chunk = len - off;
		if (chunk > B64_WRAP)
			chunk = B64_WRAP;
		if (write_all(fd, buf + off, chunk) || write_all(fd, "\n", 1))
			return (1);
		off += chunk;
	}
	return (0);
}

/*
** Encode `data` and write it to `fd`, wrapped at B64_WRAP columns. Shared with
** the DES commands for their -a (base64 armour) option.
*/
int	base64_encode_fd(int fd, const unsigned char *data, size_t len)
{
	unsigned char	*enc;
	size_t			elen;
	int				ret;

	elen = (len + 2) / 3 * 4;
	enc = malloc(elen ? elen : 1);
	if (!enc)
		return (1);
	base64_encode(enc, data, len);
	ret = write_wrapped(fd, enc, elen);
	free(enc);
	return (ret);
}

static void	b64_error(const char *name)
{
	ft_putstr_fd("ft_ssl: base64: ", 2);
	ft_putstr_fd(name, 2);
	ft_putstr_fd(": ", 2);
	ft_putstr_fd(strerror(errno), 2);
	ft_putstr_fd("\n", 2);
}

static int	load_input(t_b64_opts *o, unsigned char **data, size_t *len)
{
	if (o->infile)
	{
		if (read_file(o->infile, data, len) != 0)
			return (b64_error(o->infile), 1);
		return (0);
	}
	if (read_fd(0, data, len) != 0)
		return (b64_error("stdin"), 1);
	return (0);
}

/* ------------------------------------------------------------- run / parse */

static int	parse_b64_args(int argc, char **argv, t_b64_opts *o)
{
	int	i;

	i = 1;
	while (i < argc)
	{
		if (ft_strcmp(argv[i], "-d") == 0)
			o->decode = 1;
		else if (ft_strcmp(argv[i], "-e") == 0)
			o->decode = 0;
		else if (ft_strcmp(argv[i], "-i") == 0 && i + 1 < argc)
			o->infile = argv[++i];
		else if (ft_strcmp(argv[i], "-o") == 0 && i + 1 < argc)
			o->outfile = argv[++i];
		else
		{
			ft_putstr_fd("ft_ssl: base64: invalid option '", 2);
			ft_putstr_fd(argv[i], 2);
			ft_putstr_fd("'\n", 2);
			return (1);
		}
		i++;
	}
	return (0);
}

static int	run_base64(t_b64_opts *o, int outfd,
			const unsigned char *data, size_t len)
{
	unsigned char	*dec;
	size_t			dlen;
	int				ret;

	if (!o->decode)
		return (base64_encode_fd(outfd, data, len));
	if (base64_decode((const char *)data, len, &dec, &dlen))
		return (ft_putstr_fd("ft_ssl: base64: invalid input\n", 2), 1);
	ret = write_all(outfd, dec, dlen);
	free(dec);
	return (ret);
}

int	base64_command(const t_cipher *self, int argc, char **argv)
{
	t_b64_opts		opts;
	unsigned char	*data;
	size_t			len;
	int				outfd;
	int				ret;

	(void)self;
	opts.decode = 0;
	opts.infile = NULL;
	opts.outfile = NULL;
	if (parse_b64_args(argc, argv, &opts))
		return (1);
	if (load_input(&opts, &data, &len))
		return (1);
	outfd = 1;
	if (opts.outfile)
	{
		outfd = open(opts.outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (outfd < 0)
			return (b64_error(opts.outfile), free(data), 1);
	}
	ret = run_base64(&opts, outfd, data, len);
	free(data);
	if (outfd != 1)
		close(outfd);
	return (ret);
}
