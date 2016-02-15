/*
 *	BIRD -- Bidirectional Forwarding Detection (BFD)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "bfd.h"

#include "lib/crypto.h"

struct bfd_ctl_packet
{
  u8 vdiag;			/* version and diagnostic */
  u8 flags;			/* state and flags */
  u8 detect_mult;
  u8 length;
  u32 snd_id;			/* sender ID, aka 'my discriminator' */
  u32 rcv_id;			/* receiver ID, aka 'your discriminator' */
  u32 des_min_tx_int;
  u32 req_min_rx_int;
  u32 req_min_echo_rx_int;
};

#define BFD_MAX_PASS_LEN_SIMPLE_AUTH 16
#define BFD_MIN_PASS_LEN_SIMPLE_AUTH 1

struct bfd_simple_auth_packet_section
{
  u8 type;			/* BFD_AUTH_SIMPLE */
  u8 length;			/* The length of password + BFD_AUTH_SIMPLE_HEADER_LEN */
#define BFD_AUTH_SIMPLE_HEADER_LEN 3
#define BFD_AUTH_SIMPLE_MAX_LEN	(BFD_AUTH_SIMPLE_HEADER_LEN + BFD_MAX_PASS_LEN_SIMPLE_AUTH)
#define BFD_AUTH_SIMPLE_MIN_LEN (BFD_AUTH_SIMPLE_HEADER_LEN + BFD_MIN_PASS_LEN_SIMPLE_AUTH)
  u8 key_id;			/* This allows multiple keys to be active simultaneously */
  byte password[BFD_MAX_PASS_LEN_SIMPLE_AUTH];	/* The password is a binary string, and MUST be from 1 to 16 bytes in length.*/
};

struct bfd_crypt_auth_packet_section
{
  u8 type;			/* BFD_AUTH_KEYED_* or BFD_AUTH_METICULOUS_* */
  u8 length;			/* The length of the authentication section including the Type, Len, KeyID fields */
#define BFD_AUTH_LEN_MD5	24
#define BFD_AUTH_LEN_SHA1 	28
  u8 key_id;			/* This allows multiple keys to be active simultaneously */
  u8 must_be_zero;		/* MUST be set to zero on transmit and ignored on receipt */
  u32 csn;			/* Cryptographic Sequence Number (CSN): provides protection against replay attack */
  byte digest[SHA1_SIZE];	/* Auth Key/Hash, 20 for SHA1, 16 for MD5 */
};

#define BFD_BASE_LEN	sizeof(struct bfd_ctl_packet)
#define BFD_MAX_LEN	64

static inline u8 bfd_pack_vdiag(u8 version, u8 diag)
{ return (version << 5) | diag; }

static inline u8 bfd_pack_flags(u8 state, u8 flags)
{ return (state << 6) | flags; }

static inline u8 bfd_pkt_get_version(struct bfd_ctl_packet *pkt)
{ return pkt->vdiag >> 5; }

static inline u8 bfd_pkt_get_diag(struct bfd_ctl_packet *pkt)
{ return pkt->vdiag & 0x1f; }


static inline u8 bfd_pkt_get_state(struct bfd_ctl_packet *pkt)
{ return pkt->flags >> 6; }

static inline void bfd_pkt_set_state(struct bfd_ctl_packet *pkt, u8 val)
{ pkt->flags = val << 6; }


char *
bfd_format_flags(u8 flags, char *buf)
{
  char *bp = buf;
  if (flags & BFD_FLAGS)	*bp++ = ' ';
  if (flags & BFD_FLAG_POLL)	*bp++ = 'P';
  if (flags & BFD_FLAG_FINAL)	*bp++ = 'F';
  if (flags & BFD_FLAG_CPI)	*bp++ = 'C';
  if (flags & BFD_FLAG_AP)	*bp++ = 'A';
  if (flags & BFD_FLAG_DEMAND)	*bp++ = 'D';
  if (flags & BFD_FLAG_MULTIPOINT) *bp++ = 'M';
  *bp = 0;

  return buf;
}

static const u8 bfd_auth_to_crypto_alg_table[] = {
    [BFD_AUTH_NONE] = 			CRYPTO_ALG_UNDEFINED,
    [BFD_AUTH_SIMPLE] = 		CRYPTO_ALG_UNDEFINED,
    [BFD_AUTH_KEYED_MD5] = 		CRYPTO_ALG_MD5,
    [BFD_AUTH_METICULOUS_KEYED_MD5] = 	CRYPTO_ALG_MD5,
    [BFD_AUTH_KEYED_SHA1] = 		CRYPTO_ALG_SHA1,
    [BFD_AUTH_METICULOUS_KEYED_SHA1] = 	CRYPTO_ALG_SHA1,
};

u8
bfd_auth_to_crypto_alg(u8 bfd_auth_type)
{
  return bfd_auth_to_crypto_alg_table[bfd_auth_type];
}

static inline void
bfd_update_tx_csn(struct bfd_session *s)
{
  /* We are using real time, but enforcing monotonicity. */
  s->last_tx_csn = (s->last_tx_csn < (u32) now_real) ? (u32) now_real : s->last_tx_csn + 1;
}

/* Fill authentication section and modifies final length in control section packet */
static void
bfd_fill_authentication_section(const struct bfd_proto *p, struct bfd_session *s, struct bfd_ctl_packet *pkt)
{
  void *pkt_auth_section = (byte *) pkt + BFD_BASE_LEN;

  struct password_item *pass = password_find(s->ifa->cf->passwords, 0);

  if (!pass)
  {
    /* FIXME: This should not happen */
    log(L_ERR "%s: No suitable password found for authentication", p->p.name);
    return;
  }

  u8 bfd_auth_type = s->ifa->cf->auth_type;

  switch (bfd_auth_type)
  {
  case BFD_AUTH_SIMPLE:
  {
    struct bfd_simple_auth_packet_section *simple_auth = pkt_auth_section;

    uint final_pass_len = MIN(pass->password_len, BFD_MAX_PASS_LEN_SIMPLE_AUTH);
    simple_auth->length = BFD_AUTH_SIMPLE_HEADER_LEN + final_pass_len;
    simple_auth->type = BFD_AUTH_SIMPLE;
    simple_auth->key_id = pass->id;
    strncpy(simple_auth->password, pass->password, final_pass_len);

    pkt->length += simple_auth->length;
    break;
  }

  case BFD_AUTH_METICULOUS_KEYED_MD5:
  case BFD_AUTH_METICULOUS_KEYED_SHA1:
    bfd_update_tx_csn(s);
    /* fall through */

  case BFD_AUTH_KEYED_MD5:
  case BFD_AUTH_KEYED_SHA1:
  {
    if (s->last_tx_csn < (u32)now_real)
      bfd_update_tx_csn(s);

    DBG("[%I] CSN: %u\n", s->addr, s->last_tx_csn);

    int crypto_type = bfd_auth_to_crypto_alg_table[bfd_auth_type];
    ASSERT(crypto_type == pass->crypto_type);

    union crypto_context ctx;
    struct bfd_crypt_auth_packet_section *crypt_auth = pkt_auth_section;

    crypt_auth->type = bfd_auth_type;
    crypt_auth->key_id = pass->id;
    crypt_auth->must_be_zero = 0;

    crypt_auth->csn = htonl(s->last_tx_csn);

    if (bfd_auth_type == BFD_AUTH_KEYED_MD5  || bfd_auth_type == BFD_AUTH_METICULOUS_KEYED_MD5)
      crypt_auth->length = BFD_AUTH_LEN_MD5;
    else if (bfd_auth_type == BFD_AUTH_KEYED_SHA1 || bfd_auth_type == BFD_AUTH_METICULOUS_KEYED_SHA1)
      crypt_auth->length = BFD_AUTH_LEN_SHA1;
    else
      bug("password key type mismatch");

    pkt->length += crypt_auth->length;

    byte *hash = crypto(&ctx, pass, (const byte *) pkt, BFD_BASE_LEN);
    memcpy(crypt_auth->digest, hash, crypto_get_hash_length(pass->crypto_type));
    break;
  }
  }
}

void
bfd_send_ctl(struct bfd_proto *p, struct bfd_session *s, int final)
{
  sock *sk = s->ifa->sk;
  struct bfd_ctl_packet *pkt;
  char fb[8];

  if (!sk)
    return;

  pkt = (struct bfd_ctl_packet *) sk->tbuf;
  pkt->vdiag = bfd_pack_vdiag(1, s->loc_diag);
  pkt->flags = bfd_pack_flags(s->loc_state, 0);
  pkt->detect_mult = s->detect_mult;
  pkt->length = BFD_BASE_LEN;
  pkt->snd_id = htonl(s->loc_id);
  pkt->rcv_id = htonl(s->rem_id);
  pkt->des_min_tx_int = htonl(s->des_min_tx_new);
  pkt->req_min_rx_int = htonl(s->req_min_rx_new);
  pkt->req_min_echo_rx_int = 0;

  if (final)
    pkt->flags |= BFD_FLAG_FINAL;
  else if (s->poll_active)
    pkt->flags |= BFD_FLAG_POLL;

  if (s->ifa->cf->auth_type != BFD_AUTH_NONE)
  {
    pkt->flags |= BFD_FLAG_AP;
    bfd_fill_authentication_section(p, s, pkt);
  }

  if (sk->tbuf != sk->tpos)
    log(L_WARN "%s: Old packet overwritten in TX buffer", p->p.name);

  TRACE(D_PACKETS, "Sending CTL to %I [%s%s]", s->addr,
	bfd_state_names[s->loc_state], bfd_format_flags(pkt->flags, fb));

  sk_send_to(sk, pkt->length, s->addr, sk->dport);
}

static const char *auth_method_str[] = {
    [BFD_AUTH_SIMPLE] = "SIMPLE PASSWORD",
    [BFD_AUTH_KEYED_MD5] = "KEYED MD5",
    [BFD_AUTH_KEYED_SHA1] = "KEYED SHA1",
    [BFD_AUTH_METICULOUS_KEYED_MD5] = "METICULOUS KEYED MD5",
    [BFD_AUTH_METICULOUS_KEYED_SHA1] = "METICULOUS KEYED SHA1",
};

#define DROP(DSC,VAL) do { err_dsc = DSC; err_val = VAL; goto drop; } while(0)

#define AUTH_ERR_MSG_MAX_LEN 100
#define FMT_DROP(bfd, session, method, format, ...) 				\
  do {  									\
    log(L_REMOTE "%s: Bad %s authentication section in packet from %I - " 	\
	format, (bfd)->p.name, auth_method_str[method], (session)->addr,  ##__VA_ARGS__); \
    return 0;									\
  } while(0);

/*
 * Return 1 if authentication is valid
 * Return 0 if authentication failed
 */
static int
is_authentication_valid(const struct bfd_proto *p, struct bfd_session *s, const byte *pkt)
{
  const void *auth_section = pkt + BFD_BASE_LEN;
  const struct bfd_simple_auth_packet_section *simple_auth = auth_section;
  const struct bfd_crypt_auth_packet_section *crypt_auth = auth_section;
  const struct password_item *cfg_pass = NULL;

  u8 pkt_auth_type = simple_auth->type; /* Auth Type is common for simple even for cryptographic authentication */
  u8 cfg_auth_type = s->ifa->cf->auth_type;
  if (pkt_auth_type != cfg_auth_type)
    FMT_DROP(p, s, pkt_auth_type,
	     "authentication method mismatch, got %s, expected %s ",
	     auth_method_str[pkt_auth_type], auth_method_str[cfg_auth_type]);

  union crypto_context ctx;

  cfg_pass = password_find_by_id(s->ifa->cf->passwords, simple_auth->key_id);
  if (!cfg_pass)
    FMT_DROP(p, s, pkt_auth_type, "There is no password with id %u", simple_auth->key_id);

  switch (pkt_auth_type)
  {
  case BFD_AUTH_SIMPLE:
    if (simple_auth->length < BFD_AUTH_SIMPLE_MIN_LEN || simple_auth->length > BFD_AUTH_SIMPLE_MAX_LEN)
      FMT_DROP(p, s, pkt_auth_type, "bad size, got %d bytes, expected in the range of " STR(BFD_AUTH_SIMPLE_MIN_LEN) " and " STR(BFD_AUTH_SIMPLE_MAX_LEN) " bytes", simple_auth->length);

    char buf[BFD_MAX_PASS_LEN_SIMPLE_AUTH + 1];
    bzero(buf, sizeof(buf));
    uint pkt_pass_len = MIN(BFD_MAX_PASS_LEN_SIMPLE_AUTH, simple_auth->length - BFD_AUTH_SIMPLE_HEADER_LEN);
    bsnprintf(buf, pkt_pass_len, "%s", simple_auth->password);
    uint cfg_pass_len = MIN(cfg_pass->password_len, BFD_MAX_PASS_LEN_SIMPLE_AUTH);
    if (memcmp(buf, cfg_pass->password, cfg_pass_len))
      FMT_DROP(p, s, pkt_auth_type, "wrong password, got: %s, expected: %s", simple_auth->password, cfg_pass->password);
    break;

  case BFD_AUTH_METICULOUS_KEYED_MD5:
  case BFD_AUTH_METICULOUS_KEYED_SHA1:
  {
    u32 seq = ntohl(crypt_auth->csn);
    if (seq > s->last_rx_csn || (seq == 0 && s->last_rx_csn == 0))
      s->last_rx_csn = seq;
    else
      FMT_DROP(p, s, pkt_auth_type, "bad sequence number %u, expected was >%u", seq, s->last_rx_csn);
  } /* Fall through */

  case BFD_AUTH_KEYED_MD5:
  case BFD_AUTH_KEYED_SHA1:
  {
    u32 seq = ntohl(crypt_auth->csn);
    if (seq >= s->last_rx_csn)
      s->last_rx_csn = seq;
    else
      FMT_DROP(p, s, pkt_auth_type, "bad sequence number %u, expected was >=%u", seq, s->last_rx_csn);

    if (!is_crypto_digest_valid(&ctx, cfg_pass, pkt, BFD_BASE_LEN, crypt_auth->digest))
    {
      FMT_DROP(p, s, pkt_auth_type, "wrong cryptographic digest", cfg_pass->id);
    }
  }
  }

  return 1; /* OK */
}

static int
bfd_rx_hook(sock *sk, int len)
{
  struct bfd_proto *p =  sk->data;
  struct bfd_ctl_packet *pkt = (struct bfd_ctl_packet *) sk->rbuf;
  const char *err_dsc = NULL;
  uint err_val = 0;
  char fb[8];

  if ((sk->sport == BFD_CONTROL_PORT) && (sk->rcv_ttl < 255))
    DROP("wrong TTL", sk->rcv_ttl);

  if (len < BFD_BASE_LEN)
    DROP("too short", len);

  u8 version = bfd_pkt_get_version(pkt);
  if (version != 1)
    DROP("version mismatch", version);

  if ((pkt->length < BFD_BASE_LEN) || (pkt->length > len))
    DROP("length mismatch", pkt->length);

  if (pkt->detect_mult == 0)
    DROP("invalid detect mult", 0);

  if ((pkt->flags & BFD_FLAG_MULTIPOINT) ||
      ((pkt->flags & BFD_FLAG_POLL) && (pkt->flags & BFD_FLAG_FINAL)))
    DROP("invalid flags", pkt->flags);

  if (pkt->snd_id == 0)
    DROP("invalid my discriminator", 0);

  struct bfd_session *s;
  u32 id = ntohl(pkt->rcv_id);

  if (id)
  {
    s = bfd_find_session_by_id(p, id);

    if (!s)
      DROP("unknown session id", id);
  }
  else
  {
    u8 ps = bfd_pkt_get_state(pkt);
    if (ps > BFD_STATE_DOWN)
      DROP("invalid init state", ps);

    s = bfd_find_session_by_addr(p, sk->faddr);

    /* FIXME: better session matching and message */
    if (!s)
      return 1;
  }

  if (s->ifa->cf->auth_type != BFD_AUTH_NONE)
  {
    if (pkt->flags & BFD_FLAG_AP)
    {
      if (!is_authentication_valid(p, s, (byte *) pkt))
	DROP("authentication failed", 0);
    }
    else
      DROP("authentication is required", 0);
  }

  u32 old_tx_int = s->des_min_tx_int;
  u32 old_rx_int = s->rem_min_rx_int;

  s->rem_id= ntohl(pkt->snd_id);
  s->rem_state = bfd_pkt_get_state(pkt);
  s->rem_diag = bfd_pkt_get_diag(pkt);
  s->rem_demand_mode = pkt->flags & BFD_FLAG_DEMAND;
  s->rem_min_tx_int = ntohl(pkt->des_min_tx_int);
  s->rem_min_rx_int = ntohl(pkt->req_min_rx_int);
  s->rem_detect_mult = pkt->detect_mult;

  TRACE(D_PACKETS, "CTL received from %I [%s%s]", sk->faddr,
	bfd_state_names[s->rem_state], bfd_format_flags(pkt->flags, fb));

  bfd_session_process_ctl(s, pkt->flags, old_tx_int, old_rx_int);
  return 1;

 drop:
  log(L_REMOTE "%s: Bad packet from %I - %s (%u)", p->p.name, sk->faddr, err_dsc, err_val);
  return 1;
}

static void
bfd_err_hook(sock *sk, int err)
{
  struct bfd_proto *p = sk->data;
  log(L_ERR "%s: Socket error: %m", p->p.name, err);
}

sock *
bfd_open_rx_sk(struct bfd_proto *p, int multihop, int inet_version)
{
  sock *sk = sk_new(p->tpool);
  sk->type = SK_UDP;
  sk->sport = !multihop ? BFD_CONTROL_PORT : BFD_MULTI_CTL_PORT;
  sk->data = p;

  sk->rbsize = BFD_MAX_LEN;
  sk->rx_hook = bfd_rx_hook;
  sk->err_hook = bfd_err_hook;

  /* TODO: configurable ToS and priority */
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->priority = sk_priority_control;
  sk->flags = SKF_THREAD | SKF_LADDR_RX | (!multihop ? SKF_TTL_RX : 0);

  switch (inet_version) {
    case 4:
      sk->fam = SK_FAM_IPV4;
      sk->flags |= SKF_V4ONLY;
      break;
    case 6:
      sk->fam = SK_FAM_IPV6;
      sk->flags |= SKF_V6ONLY;
      break;
    default:
      ASSERT(0);
  }

  if (sk_open(sk) < 0)
    goto err;

  sk_start(sk);
  return sk;

 err:
  sk_log_error(sk, p->p.name);
  rfree(sk);
  return NULL;
}

sock *
bfd_open_tx_sk(struct bfd_proto *p, ip_addr local, struct iface *ifa)
{
  sock *sk = sk_new(p->tpool);
  sk->type = SK_UDP;
  sk->saddr = local;
  sk->dport = ifa ? BFD_CONTROL_PORT : BFD_MULTI_CTL_PORT;
  sk->iface = ifa;
  sk->data = p;

  sk->tbsize = BFD_MAX_LEN;
  sk->err_hook = bfd_err_hook;

  /* TODO: configurable ToS, priority and TTL security */
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->priority = sk_priority_control;
  sk->ttl = ifa ? 255 : -1;
  sk->flags = SKF_THREAD | SKF_BIND | SKF_HIGH_PORT;

  if (ipa_is_ip4(local)) {
    sk->fam = SK_FAM_IPV4;
    sk->flags |= SKF_V4ONLY;
  } else {
    sk->fam = SK_FAM_IPV6;
    sk->flags |= SKF_V6ONLY;
  }

  if (sk_open(sk) < 0)
    goto err;

  sk_start(sk);
  return sk;

 err:
  sk_log_error(sk, p->p.name);
  rfree(sk);
  return NULL;
}
