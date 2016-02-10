/*
 *	BIRD Library -- Generic wrapper for cryptographic functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "lib/crypto.h"

struct algorithm_descript {
  uint hash_length;
  const char *name;
  void (*init)(void *ctx);
  void (*init_hmac)(void *ctx, const byte *key, uint keylen);
  void (*update)(void *ctx, const byte *data, uint size);
  byte* (*final)(void *ctx);
};

#define CRYPTO_HMAC(name, len, prefix) {len, name, NULL, prefix##_hmac_init, prefix##_hmac_update, prefix##_hmac_final}
#define CRYPTO_HASH(name, len, prefix) {len, name, prefix##_init, NULL, prefix##_update, prefix##_final}

static const struct algorithm_descript crypto_table[] = {
    [CRYPTO_ALG_MD5] = 		CRYPTO_HASH("KEYED MD5",    	MD5_SIZE,    md5),
    [CRYPTO_ALG_SHA1] = 	CRYPTO_HASH("KEYED SHA-1",  	SHA1_SIZE,   sha1),
    [CRYPTO_ALG_SHA224] = 	CRYPTO_HASH("KEYED SHA-224",	SHA224_SIZE, sha224),
    [CRYPTO_ALG_SHA256] = 	CRYPTO_HASH("KEYED SHA-256",	SHA256_SIZE, sha256),
    [CRYPTO_ALG_SHA384] = 	CRYPTO_HASH("KEYED SHA-384",	SHA384_SIZE, sha384),
    [CRYPTO_ALG_SHA512] = 	CRYPTO_HASH("KEYED SHA-512",	SHA512_SIZE, sha512),
    [CRYPTO_ALG_HMAC_MD5] = 	CRYPTO_HMAC("HMAC-MD5",     	MD5_SIZE,    md5),
    [CRYPTO_ALG_HMAC_SHA1] = 	CRYPTO_HMAC("HMAC-SHA-1",   	SHA1_SIZE,   sha1),
    [CRYPTO_ALG_HMAC_SHA224] = 	CRYPTO_HMAC("HMAC-SHA-224", 	SHA224_SIZE, sha224),
    [CRYPTO_ALG_HMAC_SHA256] = 	CRYPTO_HMAC("HMAC-SHA-256", 	SHA256_SIZE, sha256),
    [CRYPTO_ALG_HMAC_SHA384] = 	CRYPTO_HMAC("HMAC-SHA-384", 	SHA384_SIZE, sha384),
    [CRYPTO_ALG_HMAC_SHA512] = 	CRYPTO_HMAC("HMAC-SHA-512", 	SHA512_SIZE, sha512),
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
crypto(union crypto_context *ctx, const struct password_item *pass, const byte *data, uint size)
{
  int type = pass->crypto_type;
  const byte *key = pass->password;
  uint keylen = pass->password_len;

  DBG("Crypto(key(%u):", pass->password_len);
  uint i;
  for(i = 0; i < pass->password_len; i++)
    DBG(" %02X", pass->password[i]);
  DBG(", data(%u):", size);
  for(i = 0; i < pass->password_len; i++)
    DBG(" %02X", data[i]);
  DBG(") -> digest(%u): ", crypto_get_hash_length(type));

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

  byte *digest = crypto_table[type].final(ctx);
  for (i = 0; i < crypto_get_hash_length(type); i++)
    DBG("%02X ", digest[i]);
  DBG("\n");

  return digest;
}

/*
 * verify a @investigate_digest
 * return 1 if @investigate_digest is valid
 * return 0 if @investigate_digest is invalid
 */
int
is_crypto_digest_valid(union crypto_context *ctx, const struct password_item *pass, const byte *data, uint size, const byte *investigate_digest)
{
  byte *expected = crypto(ctx, pass, data, size);
  if (memcmp(investigate_digest, expected, crypto_get_hash_length(pass->crypto_type)))
  {
    DBG("Digest of data with password '%s' failed: \n", pass->password);
    uint i;

    DBG("      Got: ");
    for (i = 0; i < crypto_get_hash_length(pass->crypto_type); i++)
      DBG("%02X ", investigate_digest[i]);
    DBG("\n");

    DBG(" Expected: ");
    for (i = 0; i < crypto_get_hash_length(pass->crypto_type); i++)
      DBG("%02X ", expected[i]);
    DBG("\n");

    return 0; /* FAIL */
  }
  return 1; /* OK */
}
