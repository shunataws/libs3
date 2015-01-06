#include "sha256.h"

/**
* Encode a serial object by hexadecimal encoding.
*/
void hexencode(const void *buf, int size, char *wp)
{
	const unsigned char* rp = (const unsigned char*)buf;
	//wp require: size * 2 + 1?
	const unsigned char* ep = rp + size;
	for (; rp < ep; rp++)
	{
		int num = *rp >> 4;
		if (num < 10) {
			*(wp++) = '0' + num;
		}
		else {
			*(wp++) = 'a' + num - 10;
		}
		num = *rp & 0x0f;
		if (num < 10) {
			*(wp++) = '0' + num;
		}
		else {
			*(wp++) = 'a' + num - 10;
		}
	}
	*wp = '\0';
}