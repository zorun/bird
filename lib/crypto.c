/*
 *	BIRD Library -- Generic wrapper for cryptographic functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/crypto.h"

#define CRYPTO_HMAC(name, len, prefix) {len, name, NULL, prefix##_hmac_init, prefix##_hmac_update, prefix##_hmac_final}
#define CRYPTO_HASH(name, len, prefix) {len, name, prefix##_init, NULL, prefix##_update, prefix##_final}

struct algorithm_descript {
  uint hash_length;
  const char *name;
  void (*init)(void *ctx);
  void (*init_hmac)(void *ctx, const byte *key, uint keylen);
  void (*update)(void *ctx, const byte *data, uint size);
  byte* (*final)(void *ctx);
};

static const struct algorithm_descript crypto_table[] = {
    [CRYPTO_ALG_MD5] = 		CRYPTO_HASH("KEYED MD5",    MD5_SIZE,    md5),
    [CRYPTO_ALG_SHA1] = 	CRYPTO_HASH("SHA-1", 	    SHA1_SIZE,   sha1),
    [CRYPTO_ALG_SHA224] = 	CRYPTO_HASH("SHA-224",      SHA224_SIZE, sha224),
    [CRYPTO_ALG_SHA256] = 	CRYPTO_HASH("SHA-256",      SHA256_SIZE, sha256),
    [CRYPTO_ALG_SHA384] = 	CRYPTO_HASH("SHA-384",      SHA384_SIZE, sha384),
    [CRYPTO_ALG_SHA512] = 	CRYPTO_HASH("SHA-512",      SHA512_SIZE, sha512),
    [CRYPTO_ALG_HMAC_MD5] = 	CRYPTO_HMAC("HMAC-MD5",     MD5_SIZE,    md5),
    [CRYPTO_ALG_HMAC_SHA1] = 	CRYPTO_HMAC("HMAC-SHA-1",   SHA1_SIZE,   sha1),
    [CRYPTO_ALG_HMAC_SHA224] = 	CRYPTO_HMAC("HMAC-SHA-224", SHA224_SIZE, sha224),
    [CRYPTO_ALG_HMAC_SHA256] = 	CRYPTO_HMAC("HMAC-SHA-256", SHA256_SIZE, sha256),
    [CRYPTO_ALG_HMAC_SHA384] = 	CRYPTO_HMAC("HMAC-SHA-384", SHA384_SIZE, sha384),
    [CRYPTO_ALG_HMAC_SHA512] = 	CRYPTO_HMAC("HMAC-SHA-512", SHA512_SIZE, sha512),
};

static void
check_crypto_type(int type)
{
  if (type < 1 || type > CRYPTO_ALG_MAX_VALUE)
    bug("Undefined type of cryptographic algorithm");
}

uint
crypto_get_hash_length(int type)
{
  check_crypto_type(type);
  return crypto_table[type].hash_length;
}

const char *
crypto_get_alg_name(int type)
{
  check_crypto_type(type);
  return crypto_table[type].name;
}

byte *
crypto(union crypto_context *ctx, int type, const byte *key, uint keylen, const byte *data, uint size)
{
  check_crypto_type(type);

  if (crypto_table[type].init)
  {
    crypto_table[type].init(ctx);
    crypto_table[type].update(ctx, data, size);
    uint hash_len = crypto_get_hash_length(type);
    char *padded_key = alloca(hash_len+1);
    strncpy(padded_key, key, hash_len);
    crypto_table[type].update(ctx, padded_key, hash_len);
  }
  else if (crypto_table[type].init_hmac)
  {
    crypto_table[type].init_hmac(ctx, key, keylen);
    crypto_table[type].update(ctx, data, size);
  }

  return crypto_table[type].final(ctx);
}
