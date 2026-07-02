#include "ft_ssl.h"

static const uint32_t	K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void	write_bend(unsigned char *data, uint64_t n, size_t	len)
{
	for (size_t i = 0; i < len; i++)
	{
		data[len - 1 - i] = n & 0xff;
		n >>= 8;
	}
}

static uint64_t	read_bend(const unsigned char *data, size_t len)
{
	uint64_t	ret;

	ret = 0;
	for (size_t i = 0; i < len; i++)
	{
		ret <<= 8;
		ret += data[i];
	}
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

static int	sha256_padding(const unsigned char *data, size_t len, unsigned char **pad_data)
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

	write_bend(pad_data_str, (uint64_t)len * 8, 8);
	return (0);
}

static void	get_split_chunk(uint32_t chunk[16], const unsigned char *data)
{
	for (size_t i = 0; i < 16; i++)
	{
		chunk[i] = read_bend(data, 4);
		data += 4;
	}
}

static uint32_t	rrot(uint32_t n, int s)
{
	return (n >> s | n << (32 - s));
}

void	sha256_hash(const unsigned char *data, size_t len,
			unsigned char *digest)
{
	unsigned char	*pad_data;
	size_t			n_chunks;
	uint32_t		w[64];
	uint32_t		a[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
							0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	uint32_t		tmp[8];

	sha256_padding(data, len, &pad_data);
	n_chunks = get_padded_len(len) / CHUNK_SIZE;
	for (size_t i = 0; i < n_chunks; i++)
	{
		ft_memcpy(tmp, a, sizeof(uint32_t) * 8);
		get_split_chunk(w, pad_data + i * CHUNK_SIZE);
		for (int i = 16; i < 64; i++)
		{
			uint32_t	s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ w[i-15] >> 3;
			uint32_t	s1 = rrot(w[i-2], 17) ^ rrot(w[i-2], 19) ^ w[i-2] >> 10;
			w[i] = w[i - 7] + w[i - 16] + s0 + s1;
		}
		for (int i = 0; i < 64; i++)
		{
			uint32_t	s1 = rrot(tmp[4], 6) ^ rrot(tmp[4], 11) ^ rrot(tmp[4], 25);
			uint32_t	ch = (tmp[4] & tmp[5]) ^ (~tmp[4] & tmp[6]);
			uint32_t	temp1 = tmp[7] + s1 + ch + K[i] + w[i];
			uint32_t	s0 = rrot(tmp[0], 2) ^ rrot(tmp[0], 13) ^ rrot(tmp[0], 22);
			uint32_t	maj = (tmp[0] & tmp[1]) ^ (tmp[0] & tmp[2]) ^ (tmp[1] & tmp[2]);
			uint32_t	temp2 = s0 + maj;
	
			tmp[7] = tmp[6];
			tmp[6] = tmp[5];
			tmp[5] = tmp[4];
			tmp[4] = tmp[3] + temp1;
			tmp[3] = tmp[2];
			tmp[2] = tmp[1];
			tmp[1] = tmp[0];
			tmp[0] = temp1 + temp2;
		}
		for (int i = 0; i < 8; i++)
			a[i] += tmp[i];
	}
	for (int i = 0; i < 8; i++)
	{
		write_bend(digest, a[i], 4);
		digest += 4;
	}
	free(pad_data);
}
