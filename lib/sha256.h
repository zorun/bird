/*
 *	BIRD Library -- SHA-256 and SHA-224 Hash Functions,
 *			HMAC-SHA-256 and HMAC-SHA-224 Functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA256_H_
#define _BIRD_SHA256_H_

#include "nest/bird.h"


#define SHA224_SIZE 		28
#define SHA224_HEX_SIZE		57
#define SHA224_BLOCK_SIZE 	64

#define SHA256_SIZE 		32
#define SHA256_HEX_SIZE		65
#define SHA256_BLOCK_SIZE 	64


struct sha256_context {
  u32  h0, h1, h2, h3, h4, h5, h6, h7;
  byte buf[SHA256_BLOCK_SIZE];
  uint nblocks;
  uint count;
};

#define sha224_context sha256_context


void sha256_init(void *sha256_context);
void sha224_init(void *sha224_context);

void sha256_update(void *sha256_context, const byte *data, uint size);
static inline void sha224_update(void *sha224_context, const byte *data, uint size)
{ sha256_update(sha224_context, data, size); }

byte *sha256_final(void *sha256_context);
static inline byte *sha224_final(void *sha224_context)
{ return sha256_final(sha224_context); }


/*
 *	HMAC-SHA256, HMAC-SHA224
 */

struct sha256_hmac_context
{
  struct sha256_context ictx;
  struct sha256_context octx;
};

#define sha224_hmac_context sha256_hmac_context


void sha256_hmac_init(void *sha256_hmac_context, const byte *key, uint keylen);
void sha224_hmac_init(void *sha224_hmac_context, const byte *key, uint keylen);

void sha256_hmac_update(void *sha256_hmac_context, const byte *data, uint size);
void sha224_hmac_update(void *sha224_hmac_context, const byte *data, uint size);

byte *sha256_hmac_final(void *sha256_hmac_context);
byte *sha224_hmac_final(void *sha224_hmac_context);


#endif /* _BIRD_SHA256_H_ */
