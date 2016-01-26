/*
 *	BIRD Library -- SHA-512 and SHA-384 Hash Functions,
 *			HMAC-SHA-512 and HMAC-SHA-384 Functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA512_H_
#define _BIRD_SHA512_H_

#include "nest/bird.h"


#define SHA384_SIZE 		48
#define SHA384_HEX_SIZE		97
#define SHA384_BLOCK_SIZE	128

#define SHA512_SIZE 		64
#define SHA512_HEX_SIZE		129
#define SHA512_BLOCK_SIZE	128


struct sha512_context {
  u64 h0, h1, h2, h3, h4, h5, h6, h7;
  byte buf[SHA512_BLOCK_SIZE];
  uint nblocks;
  uint count;
};

#define sha384_context sha512_context


void sha512_init(void *sha512_context);
void sha384_init(void *sha384_context);

void sha512_update(void *sha512_context, const byte *data, uint size);
static inline void sha384_update(void *sha384_context, const byte *data, uint size)
{ sha512_update(sha384_context, data, size); }

byte *sha512_final(void *sha512_context);
static inline byte *sha384_final(void *sha384_context)
{ return sha512_final(sha384_context); }


/*
 *	HMAC-SHA512, HMAC-SHA384
 */

struct sha512_hmac_context
{
  struct sha512_context ictx;
  struct sha512_context octx;
};

#define sha384_hmac_context sha512_hmac_context


void sha512_hmac_init(void *sha512_hmac_context, const byte *key, uint keylen);
void sha384_hmac_init(void *sha384_hmac_context, const byte *key, uint keylen);

void sha512_hmac_update(void *sha512_hmac_context, const byte *buf, uint buflen);
void sha384_hmac_update(void *sha384_hmac_context, const byte *buf, uint buflen);

byte *sha512_hmac_final(void *sha512_hmac_context);
byte *sha384_hmac_final(void *sha384_hmac_context);


#endif /* _BIRD_SHA512_H_ */
