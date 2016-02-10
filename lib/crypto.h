/*
 *	BIRD Library -- Generic wrap for cryptographic functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CRYPTO_H_
#define _BIRD_CRYPTO_H_

#include "nest/bird.h"
#include "lib/md5.h"
#include "lib/sha1.h"
#include "lib/sha256.h"
#include "lib/sha512.h"
#include "lib/password.h"

#define CRYPTO_ALG_NONE		0
#define CRYPTO_ALG_MD5		1
#define CRYPTO_ALG_SHA1		2
#define CRYPTO_ALG_SHA224	3
#define CRYPTO_ALG_SHA256	4
#define CRYPTO_ALG_SHA384	5
#define CRYPTO_ALG_SHA512	6
#define CRYPTO_ALG_HMAC_MD5	7
#define CRYPTO_ALG_HMAC_SHA1	8
#define CRYPTO_ALG_HMAC_SHA224	9
#define CRYPTO_ALG_HMAC_SHA256	10
#define CRYPTO_ALG_HMAC_SHA384	11
#define CRYPTO_ALG_HMAC_SHA512	12
#define CRYPTO_ALG_MAX_VALUE CRYPTO_ALG_HMAC_SHA512 /* the last one and the longest hash as well */

union crypto_context {
  struct md5_context md5;
  struct sha1_context sha1;
  struct sha224_context sha224;
  struct sha256_context sha256;
  struct sha384_context sha384;
  struct sha512_context sha512;
  struct md5_hmac_context hmac_md5;
  struct sha1_hmac_context hmac_sha1;
  struct sha224_hmac_context hmac_sha224;
  struct sha256_hmac_context hmac_sha256;
  struct sha384_hmac_context hmac_sha384;
  struct sha512_hmac_context hmac_sha512;
};

byte *crypto(union crypto_context *ctx, const struct password_item *pass, const byte *data, uint size);
int is_crypto_digest_valid(union crypto_context *ctx, const struct password_item *pass, const byte *data, uint size, const byte *investigate_digest);
uint crypto_get_hash_length(int type);
const char *crypto_get_alg_name(int type);

#endif /* _BIRD_CRYPTO_H_ */
