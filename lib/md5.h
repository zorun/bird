/*
 *	BIRD Library -- MD5 Hash Function and HMAC-MD5 Function
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Adapted for BIRD by Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MD5_H_
#define _BIRD_MD5_H_

#include "nest/bird.h"


#define MD5_SIZE		16
#define MD5_HEX_SIZE		33
#define MD5_BLOCK_SIZE		64


struct md5_context {
  u32 buf[4];
  u32 bits[2];
  byte in[64];
};

void md5_init(void *md5_context);
void md5_update(void *md5_context, const byte *data, uint size);
byte *md5_final(void *md5_context);


/*
 *	HMAC-MD5
 */

struct md5_hmac_context {
  struct md5_context ictx;
  struct md5_context octx;
};

void md5_hmac_init(void *md5_hmac_context, const byte *key, uint keylen);
void md5_hmac_update(void *md5_hmac_context, const byte *data, uint size);
byte *md5_hmac_final(void *md5_hmac_context);


#endif /* _BIRD_MD5_H_ */
