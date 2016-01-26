/*
 *	BIRD Library -- SHA-1 Hash Function (FIPS 180-1, RFC 3174) and HMAC-SHA-1
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libucw-6.4
 *	(c) 2008--2009 Martin Mares <mj@ucw.cz>
 *
 *	Based on the code from libgcrypt-1.2.3, which is
 *	(c) 1998, 2001, 2002, 2003 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA1_H_
#define _BIRD_SHA1_H_

#include "nest/bird.h"


#define SHA1_SIZE		20	/* Size of the SHA1 hash in its binary representation */
#define SHA1_HEX_SIZE		41	/* Buffer length for a string containing SHA1 in hexadecimal format. */
#define SHA1_BLOCK_SIZE		64	/* SHA1 splits input to blocks of this size. */


/*
 * Internal SHA1 state.
 * You should use it just as an opaque handle only.
 */
struct sha1_context {
  u32 h0, h1, h2, h3, h4;
  byte buf[SHA1_BLOCK_SIZE];
  uint nblocks;
  uint count;
};

/* Initialize new algorithm run in the @sha1_context. */
void sha1_init(void *sha1_context);

/*
 * Push another @size bytes of data pointed to by @data onto the SHA1 hash
 * currently in @sha1_context. You can call this any times you want on the same hash (and
 * you do not need to reinitialize it by @sha1_init()). It has the same effect
 * as concatenating all the data together and passing them at once.
 */
void sha1_update(void *sha1_context, const byte *data, uint size);

/*
 * No more @sha1_update() calls will be done. This terminates the hash and
 * returns a pointer to it.
 *
 * Note that the pointer points into data in the @ctx context. If it ceases to
 * exist, the pointer becomes invalid.
 */
byte *sha1_final(void *sha1_context);

/*
 * A convenience one-shot function for SHA1 hash. It is equivalent to this
 * snippet of code:
 *
 *  sha1_context ctx;
 *  sha1_init(&ctx);
 *  sha1_update(&ctx, buffer, length);
 *  memcpy(outbuf, sha1_final(&ctx), SHA1_SIZE);
 */
void sha1_hash_buffer(byte *outbuf, const byte *buffer, uint length);

/*
 * SHA1 HMAC message authentication. If you provide @key and @data, the result
 * will be stored in @outbuf.
 */
void sha1_hmac(byte *outbuf, const byte *key, uint keylen, const byte *data, uint datalen);

/*
 * The HMAC also exists in a stream version in a way analogous to the plain
 * SHA1. Pass this as a context.
 */
struct sha1_hmac_context {
  struct sha1_context ictx;
  struct sha1_context octx;
};

void sha1_hmac_init(void *sha1_hmac_context, const byte *key, uint keylen);
void sha1_hmac_update(void *sha1_hmac_context, const byte *data, uint size);
byte *sha1_hmac_final(void *sha1_hmac_context);


#endif /* _BIRD_SHA1_H_ */
