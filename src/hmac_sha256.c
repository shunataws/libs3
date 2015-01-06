
#include "sha256.h"

//-------------------------------------------------------------------------

void hmac_sha256_vector(const unsigned char *key, int key_len, int num_elem,
	const unsigned char *addr[], const int *len, unsigned char *mac)
{
	unsigned char k_pad[64]; /** padding - key XORd with ipad/opad */
	unsigned char tk[32];
	const unsigned char *_addr[6];
	int _len[6], i;

	if (num_elem > 5)
	{
		/**
		* Fixed limit on the number of fragments to avoid having to
		* allocate memory (which could fail).
		*/
		return;
	}

	/** if key is longer than 64 bytes reset it to key = SHA256(key) */
	if (key_len > 64)
	{
		sha256_vector(1, &key, &key_len, tk);
		key = tk;
		key_len = 32;
	}

	/** the HMAC_SHA256 transform looks like:
	*
	* SHA256(K XOR opad, SHA256(K XOR ipad, text))
	*
	* where K is an n byte key
	* ipad is the byte 0x36 repeated 64 times
	* opad is the byte 0x5c repeated 64 times
	* and text is the data being protected */

	/** start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/** XOR key with ipad values */
	for (i = 0; i < 64; i++)
	{
		k_pad[i] ^= 0x36;
	}

	/** perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++)
	{
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	sha256_vector(1 + num_elem, _addr, _len, mac);

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/** XOR key with opad values */
	for (i = 0; i < 64; i++)
	{
		k_pad[i] ^= 0x5c;
	}

	/** perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA256_MAC_LEN;
	sha256_vector(2, _addr, _len, mac);
}

//-------------------------------------------------------------------------

void HMAC_SHA256(unsigned char hmac[32], const unsigned char *key, int key_len,
	const unsigned char *data, int data_len)
{
	hmac_sha256_vector(key, key_len, 1, &data, &data_len, hmac);
}

//-------------------------------------------------------------------------

void sha256_prf(const unsigned char *key, int key_len, const char *label, const
	unsigned char *data, int data_len, unsigned char *buf, int buf_len)
{
	unsigned short counter = 1;
	int pos, plen;
	unsigned char hash[SHA256_MAC_LEN];
	const unsigned char *addr[4];
	int len[4];
	unsigned char counter_le[2], length_le[2];

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = (unsigned char*)label;
	len[1] = strlen(label);
	addr[2] = data;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	SHA256_PUT_LE16(length_le, buf_len * 8);
	pos = 0;
	while (pos < buf_len)
	{
		plen = buf_len - pos;
		SHA256_PUT_LE16(counter_le, counter);
		if (plen >= SHA256_MAC_LEN)
		{
			hmac_sha256_vector(key, key_len, 4, addr, len, &buf[pos]);
			pos += SHA256_MAC_LEN;
		}
		else
		{
			hmac_sha256_vector(key, key_len, 4, addr, len, hash);
			memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}
}
