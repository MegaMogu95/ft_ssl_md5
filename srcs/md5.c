#include "ft_ssl.h"

static const uint32_t	K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const int	s[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static void	write_lend(unsigned char *data, uint64_t n, size_t	len)
{
	for (size_t i = 0; i < len; i++)
	{
		data[i] = n & 0xff;
		n >>= 8;
	}
}

static uint64_t	read_lend(const unsigned char *data, size_t len)
{
	uint64_t	ret;

	ret = 0;
	for (size_t i = 0; i < len; i++)
		ret += (uint64_t)data[i] << (i * 8);
	return (ret);
}

static size_t	get_padded_len(size_t len)
{
	size_t	new_len;

	new_len = len + 1 + 8;
	if (new_len % 64 > 0)
		new_len += 64 - new_len % 64;
	return (new_len);
}

static int	md5_padding(const unsigned char *data, size_t len, unsigned char **pad_data)
{
	size_t			new_len;
	unsigned char	*pad_data_str;

	new_len = get_padded_len(len);

	*pad_data = malloc(new_len);
	if (!*pad_data)
		return (1);

	pad_data_str = *pad_data;
	ft_memcpy(pad_data_str, data, len);
	pad_data_str += len;

	*pad_data_str = 0x80;
	pad_data_str++;

	ft_memset(pad_data_str, 0, new_len - (len + 1 + 8));
	pad_data_str += new_len - (len + 1 + 8);

	write_lend(pad_data_str, (uint64_t)len * 8, 8);
	return (0);
}

static void	get_split_chunk(uint32_t chunk[16], const unsigned char *data)
{
	for (size_t i = 0; i < 16; i++)
	{
		chunk[i] = read_lend(data, 4);
		data += 4;
	}
}

static uint32_t	lrot(uint32_t n, int s)
{
	return (n << s | n >> (32 - s));
}

void	md5_hash(const unsigned char *data, size_t len, unsigned char *digest)
{
	unsigned char	*pad_data;
	uint32_t		schunk[CHUNK_SIZE / sizeof(uint32_t)];
	size_t			n_chunks;
	uint32_t		a[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	uint32_t		tmp[4];
	uint32_t		f;
	int				g;

	md5_padding(data, len, &pad_data);
	n_chunks = get_padded_len(len) / CHUNK_SIZE;
	for (size_t i = 0; i < n_chunks; i++)
	{
		get_split_chunk(schunk, pad_data + i * CHUNK_SIZE);
		ft_memcpy(tmp, a, sizeof(uint32_t) * 4);
		for (int i = 0; i < 64; i++)
		{
			if (i < 16)
			{
				f = (tmp[1] & tmp[2]) | (~tmp[1] & tmp[3]);
				g = i;
			}
			else if (i < 32)
			{
				f = (tmp[3] & tmp[1]) | ( ~tmp[3] & tmp[2]);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48)
			{
				f = tmp[1] ^ tmp[2] ^ tmp[3];
				g = (3 * i + 5) % 16;
			}
			else
			{
				f = tmp[2] ^ (tmp[1] | ~tmp[3]);
				g = 7 * i % 16;
			}
			f += tmp[0] + K[i] + schunk[g];
			tmp[0] = tmp[3];
			tmp[3] = tmp[2];
			tmp[2] = tmp[1];
			tmp[1] += lrot(f, s[i]);
		}
		a[0] += tmp[0];
		a[1] += tmp[1];
		a[2] += tmp[2];
		a[3] += tmp[3];
	}
	for (int i = 0; i < 4; i++)
	{
		write_lend(digest, a[i], 4);
		digest += 4;
	}
	free(pad_data);
}
