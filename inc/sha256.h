
#ifndef WIN32
#include <util.h>
#else
#include <crtdefs.h>
#endif // _DEBUG
#include <string.h>
#include <memory.h>

#ifndef SHA256_H
#define SHA256_H

#define SHA256_MAC_LEN 32

#define SHA256_GET_LE16(a) ((unsigned short)(((a)[1] << 8) | (a)[0]))
#define SHA256_PUT_LE16(a, val)                     \
		do {								        \
			     (a)[1] = ((unsigned short)(val)) >> 8;   \
			     (a)[0] = ((unsigned short)(val)) & 0xff; \
		} while (0);

#define SHA256_GET_BE32(a) ((((unsigned int)(a)[0]) << 24) | (((unsigned int)(a)[1]) << 16) | \
                        (((unsigned int) (a)[2]) << 8)  | ((unsigned int) (a)[3]))
#define SHA256_PUT_BE32(a, val)                                            \
        do {                                                               \
                 (a)[0] = (unsigned char) ((((unsigned int) (val)) >> 24) & 0xff);   \
                 (a)[1] = (unsigned char) ((((unsigned int) (val)) >> 16) & 0xff);   \
                 (a)[2] = (unsigned char) ((((unsigned int) (val)) >> 8) & 0xff);    \
                 (a)[3] = (unsigned char) (((unsigned int) (val)) & 0xff);           \
         } while (0)

#define SHA256_PUT_BE64(a, val)                                    \
        do {                                                       \
                 (a)[0] = (unsigned char) (((unsigned long long) (val)) >> 56);    \
                 (a)[1] = (unsigned char) (((unsigned long long) (val)) >> 48);    \
                 (a)[2] = (unsigned char) (((unsigned long long) (val)) >> 40);    \
                 (a)[3] = (unsigned char) (((unsigned long long) (val)) >> 32);    \
                 (a)[4] = (unsigned char) (((unsigned long long) (val)) >> 24);    \
                 (a)[5] = (unsigned char) (((unsigned long long) (val)) >> 16);    \
                 (a)[6] = (unsigned char) (((unsigned long long) (val)) >> 8);     \
                 (a)[7] = (unsigned char) (((unsigned long long) (val)) & 0xff);   \
        } while (0)


#ifdef __cplusplus
#pragma warning(disable: 4127)
extern "C" {
#endif

	/// <summary>
	/// HMAC-SHA256 over data vector (RFC 2104)
	/// </summary>
	/// <param name="key">Key for HMAC operations</param>
	/// <param name="key_len">Length of the key in bytes</param>
	/// <param name="num_elem">Number of elements in the data vector</param>
	/// <param name="addr">Pointers to the data areas</param>
	/// <param name="len">Lengths of the data blocks</param>
	/// <param name="mac">Buffer for the hash (32 bytes)</param>
	void hmac_sha256_vector(const unsigned char *key, int key_len, int num_elem,
		const unsigned char *addr[], const int *len, unsigned char *mac);

	/// <summary>
	/// HMAC-SHA256 over data buffer (RFC 2104)
	/// </summary>
	/// <param name="hmac">Buffer for the hash (32 bytes)</param>
	/// <param name="key">Key for HMAC operations</param>
	/// <param name="key_len">Length of the key in bytes</param>
	/// <param name="data">Pointers to the data area</param>
	/// <param name="data_len">Length of the data area</param>
	void HMAC_SHA256(unsigned char hmac[32], const unsigned char *key, int key_len,
		const unsigned char *message, int message_len);

	/// <summary>
	/// SHA256-based Pseudo-Random Function (IEEE 802.11r, 8.5.1.5.2)
	///     This function is used to derive new, cryptographically separate keys
	///     from a given key.
	/// </summary>
	/// <param name="key">Key for PRF</param>
	/// <param name="key_len">Length of the key in bytes</param>
	/// <param name="label">A unique label for each purpose of the PRF</param>
	/// <param name="data">Extra data to bind into the key</param>
	/// <param name="data_len">Length of the data</param>
	/// <param name="buf">Buffer for the generated pseudo-random key</param>
	/// <param name="buf_len">Number of bytes of key to generate</param>
	void sha256_prf(const unsigned char *key, int key_len, const char *label,
		const unsigned char *data, int data_len, unsigned char *buf, int buf_len);

	/// <summary>
	/// SHA256 hash for data vector
	/// </summary>
	/// <param name="num_elem">Number of elements in the data vector</param>
	/// <param name="addr">Pointers to the data areas</param>
	/// <param name="len">Lengths of the data blocks</param>
	/// <param name="mac">Buffer for the hash</param>
	/// <returns>0 on success, -1 of failure</returns>
	int sha256_vector(int num_elem, const unsigned char *addr[], const int *len,
		unsigned char *mac);

	/// <summary>
	/// Encode a serial object by hexadecimal encoding.
	/// </summary>
	void hexencode(const void *buf, int size, char *wp);

#ifdef __cplusplus
}
#endif

#endif /** SHA256_H */

