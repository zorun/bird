/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#undef LOCAL_DEBUG

#include "rpki.h"
#include "transport.h"
#include "packets.h"

#define RPKI_ADD_FLAG 		1
#define RPKI_DELETE_FLAG	0

enum rpki_transmit_type {
  RPKI_RECV 			= 0,
  RPKI_SEND 			= 1,
};

enum pdu_error_type {
  CORRUPT_DATA 			= 0,
  INTERNAL_ERROR 		= 1,
  NO_DATA_AVAIL 		= 2,
  INVALID_REQUEST 		= 3,
  UNSUPPORTED_PROTOCOL_VER 	= 4,
  UNSUPPORTED_PDU_TYPE 		= 5,
  WITHDRAWAL_OF_UNKNOWN_RECORD 	= 6,
  DUPLICATE_ANNOUNCEMENT 	= 7,
  PDU_TOO_BIG 			= 32
};

static const char *str_pdu_error_type[] = {
  [CORRUPT_DATA] 		= "Corrupt-Data",
  [INTERNAL_ERROR] 		= "Internal-Error",
  [NO_DATA_AVAIL] 		= "No-Data-Available",
  [INVALID_REQUEST] 		= "Invalid-Request",
  [UNSUPPORTED_PROTOCOL_VER] 	= "Unsupported-Protocol-Version",
  [UNSUPPORTED_PDU_TYPE] 	= "Unsupported-PDU-Type",
  [WITHDRAWAL_OF_UNKNOWN_RECORD]= "Withdrawal-Of-Unknown-Record",
  [DUPLICATE_ANNOUNCEMENT] 	= "Duplicate-Announcement",
  [PDU_TOO_BIG] 		= "PDU-Too-Big",
};

enum pdu_type {
  SERIAL_NOTIFY 		= 0,
  SERIAL_QUERY 			= 1,
  RESET_QUERY 			= 2,
  CACHE_RESPONSE 		= 3,
  IPV4_PREFIX 			= 4,
  RESERVED 			= 5,
  IPV6_PREFIX			= 6,
  END_OF_DATA 			= 7,
  CACHE_RESET 			= 8,
  ROUTER_KEY 			= 9,
  ERROR 			= 10,
  PDU_TYPE_MAX
};

static const char *str_pdu_type[] = {
  [SERIAL_NOTIFY] 		= "Serial Notify",
  [SERIAL_QUERY] 		= "Serial Query",
  [RESET_QUERY] 		= "Reset Query",
  [CACHE_RESPONSE] 		= "Cache Response",
  [IPV4_PREFIX] 		= "IPv4 Prefix",
  [RESERVED] 			= "Reserved",
  [IPV6_PREFIX] 		= "IPv6 Prefix",
  [END_OF_DATA] 		= "End of Data",
  [CACHE_RESET] 		= "Cache Reset",
  [ROUTER_KEY] 			= "Router Key",
  [ERROR] 			= "Error"
};

/*
 *  0          8          16         24        31
 * .-------------------------------------------.
 * | Protocol |   PDU    |                     |
 * | Version  |   Type   |    reserved = zero  |
 * |  0 or 1  |  0 - 10  |                     |
 * +-------------------------------------------+
 * |                                           |
 * |                 Length >= 8               |
 * |                                           |
 * `-------------------------------------------' */
struct pdu_header {
  u8 ver;
  u8 type;
  u16 reserved;
  u32 len;
} PACKED;

struct pdu_cache_response {
  u8 ver;
  u8 type;
  u16 session_id;
  u32 len;
} PACKED;

struct pdu_serial_notify {
  u8 ver;
  u8 type;
  u16 session_id;
  u32 len;
  u32 serial_num;
} PACKED;

struct pdu_serial_query {
  u8 ver;
  u8 type;
  u16 session_id;
  u32 len;
  u32 serial_num;
} PACKED;

struct pdu_ipv4 {
  u8 ver;
  u8 type;
  u16 reserved;
  u32 len;
  u8 flags;
  u8 prefix_len;
  u8 max_prefix_len;
  u8 zero;
  ip4_addr prefix;
  u32 asn;
} PACKED;

struct pdu_ipv6 {
  u8 ver;
  u8 type;
  u16 reserved;
  u32 len;
  u8 flags;
  u8 prefix_len;
  u8 max_prefix_len;
  u8 zero;
  ip6_addr prefix;
  u32 asn;
} PACKED;

/*
 *  0          8          16         24        31
 *  .-------------------------------------------.
 *  | Protocol |   PDU    |                     |
 *  | Version  |   Type   |     Error Code      |
 *  |    1     |    10    |                     |
 *  +-------------------------------------------+
 *  |                                           |
 *  |                  Length                   |
 *  |                                           |
 *  +-------------------------------------------+
 *  |                                           |
 *  |       Length of Encapsulated PDU          |
 *  |                                           |
 *  +-------------------------------------------+
 *  |                                           |
 *  ~           Copy of Erroneous PDU           ~
 *  |                                           |
 *  +-------------------------------------------+
 *  |                                           |
 *  |           Length of Error Text            |
 *  |                                           |
 *  +-------------------------------------------+
 *  |                                           |
 *  |              Arbitrary Text               |
 *  |                    of                     |
 *  ~          Error Diagnostic Message         ~
 *  |                                           |
 *  `-------------------------------------------' */
struct pdu_error {
  u8 ver;
  u8 type;
  u16 error_code;
  u32 len;
  u32 len_enc_pdu;		/* Length of Encapsulated PDU */
  u8 rest[];			/* Copy of Erroneous PDU
				 * Length of Error Text
				 * Error Diagnostic Message */
} PACKED;

struct pdu_reset_query {
  u8 ver;
  u8 type;
  u16 flags;
  u32 len;
} PACKED;

struct pdu_end_of_data_v0 {
  u8 ver;
  u8 type;
  u16 session_id;
  u32 len;
  u32 serial_num;
} PACKED;

struct pdu_end_of_data_v1 {
  u8 ver;
  u8 type;
  u16 session_id;
  u32 len;
  u32 serial_num;
  u32 refresh_interval;
  u32 retry_interval;
  u32 expire_interval;
} PACKED;

static const size_t min_pdu_size[] = {
  [SERIAL_NOTIFY] 		= sizeof(struct pdu_serial_notify),
  [SERIAL_QUERY] 		= sizeof(struct pdu_serial_query),
  [RESET_QUERY] 		= sizeof(struct pdu_reset_query),
  [CACHE_RESPONSE] 		= sizeof(struct pdu_cache_response),
  [IPV4_PREFIX] 		= sizeof(struct pdu_ipv4),
  [RESERVED] 			= sizeof(struct pdu_header),
  [IPV6_PREFIX] 		= sizeof(struct pdu_ipv6),
  [END_OF_DATA] 		= sizeof(struct pdu_end_of_data_v0),
  [CACHE_RESET] 		= sizeof(struct pdu_cache_response),
  [ROUTER_KEY] 			= sizeof(struct pdu_header), /* FIXME */
  [ERROR] 			= 16,
};

static int rpki_send_error_pdu(struct rpki_cache *cache, const void *erroneous_pdu, const u32 err_pdu_len, const enum pdu_error_type error_code, const char *text, const u32 text_len);

static inline enum
pdu_type get_pdu_type(const void *pdu)
{
  return *((byte *) pdu + 1);
}

static void
rpki_pdu_to_network_byte_order(void *pdu)
{
  struct pdu_header *header = pdu;

  header->reserved = htons(header->reserved);
  header->len = htonl(header->len);

  const enum pdu_type type = get_pdu_type(pdu);
  switch (type)
  {
  case SERIAL_QUERY:
  {
    /* Note that a session_id is converted using converting header->reserved */
    struct pdu_serial_query *sq_pdu = pdu;
    sq_pdu->serial_num = htonl(sq_pdu->serial_num);
    break;
  }

  case ERROR:
  {
    struct pdu_error *err = pdu;
    u32 *err_text_len = (u32 *)(err->rest + err->len_enc_pdu);
    *err_text_len = htonl(*err_text_len);
    err->len_enc_pdu = htonl(err->len_enc_pdu);
    break;
  }

  case RESET_QUERY:
    break;

  default:
    bug("PDU type %s should not be sent by router!", str_pdu_type[type]);
  }
}

static void
rpki_pdu_header_to_host_byte_order(void *pdu)
{
  struct pdu_header *header = pdu;

  /* The ROUTER_KEY PDU has two 1 Byte fields instead of the 2 Byte reserved field. */
  if (header->type != ROUTER_KEY)
    header->reserved = ntohs(header->reserved);

  header->len = ntohl(header->len);
}

static void
rpki_pdu_body_to_host_byte_order(void *pdu)
{
  const enum pdu_type type = get_pdu_type(pdu);
  struct pdu_header *header = pdu;

  switch (type)
  {
  case SERIAL_NOTIFY:
  {
    /* Note that a session_id is converted using converting header->reserved */
    struct pdu_serial_notify *sn_pdu = pdu;
    sn_pdu->serial_num = ntohl(sn_pdu->serial_num);
    break;
  }

  case END_OF_DATA:
  {
    /* Note that a session_id is converted using converting header->reserved */
    struct pdu_end_of_data_v0 *eod0 = pdu;
    eod0->serial_num = ntohl(eod0->serial_num); /* same either for version 1 */

    if (header->ver == RPKI_VERSION_1)
    {
      struct pdu_end_of_data_v1 *eod1 = pdu;
      eod1->expire_interval = ntohl(eod1->expire_interval);
      eod1->refresh_interval = ntohl(eod1->refresh_interval);
      eod1->retry_interval = ntohl(eod1->retry_interval);
    }
    break;
  }

  case IPV4_PREFIX:
  {
    struct pdu_ipv4 *ipv4 = pdu;
    ipv4->prefix = ip4_ntoh(ipv4->prefix);
    ipv4->asn = ntohl(ipv4->asn);
    break;
  }

  case IPV6_PREFIX:
  {
    struct pdu_ipv6 *ipv6 = pdu;
    ipv6->prefix = ip6_ntoh(ipv6->prefix);
    ipv6->asn = ntohl(ipv6->asn);
    break;
  }

  case ERROR:
  {
    /* Note that a error_code is converted using converting header->reserved */
    struct pdu_error *err = pdu;
    err->len_enc_pdu = ntohl(err->len_enc_pdu);
    u32 *err_text_len = (u32 *)(err->rest + err->len_enc_pdu);
    *err_text_len = htonl(*err_text_len);
    break;
  }

  case ROUTER_KEY:
  case SERIAL_QUERY:
  case RESET_QUERY:
  case CACHE_RESPONSE:
  case CACHE_RESET:
    break;
  }
}

/**
 * rpki_convert_pdu_back_to_network_byte_order - convert host-byte order PDU back to network-byte order
 * @pdu: host-byte order PDU
 *
 * Assumed: |A == ntohl(ntohl(A))|
 */
static void
rpki_convert_pdu_back_to_network_byte_order(void *pdu)
{
  rpki_pdu_header_to_host_byte_order(pdu);
  rpki_pdu_body_to_host_byte_order(pdu);
}

static void
rpki_log_packet(struct rpki_cache *cache, const void *pdu, const enum rpki_transmit_type action)
{
  if (!(cache->p->p.debug & D_PACKETS))
    return;

  const char *str_type = str_pdu_type[get_pdu_type(pdu)];
  const struct pdu_header *header = pdu;

  char detail[128];
  switch (header->type)
  {
  case SERIAL_NOTIFY:
  case SERIAL_QUERY:
    bsnprintf(detail, sizeof(detail), "(session id: %u, serial number: %u)", header->reserved, ((struct pdu_serial_notify *) header)->serial_num);
    break;

  case END_OF_DATA:
  {
    const struct pdu_end_of_data_v1 *eod = pdu;
    if (eod->ver == RPKI_VERSION_1)
      bsnprintf(detail, sizeof(detail), "(session id: %u, serial number: %u, refresh: %us, retry: %us, expire: %us)", eod->session_id, eod->serial_num, eod->refresh_interval, eod->retry_interval, eod->expire_interval);
    else
      bsnprintf(detail, sizeof(detail), "(session id: %u, serial number: %u)", eod->session_id, eod->serial_num);
    break;
  }

  case CACHE_RESPONSE:
    bsnprintf(detail, sizeof(detail), "(session id: %u)", header->reserved);
    break;

  case IPV4_PREFIX:
  {
    const struct pdu_ipv4 *ipv4 = pdu;
    bsnprintf(detail, sizeof(detail), "(%I4/%u-%u AS%u)", ipv4->prefix, ipv4->prefix_len, ipv4->max_prefix_len, ipv4->asn);
    break;
  }

  case IPV6_PREFIX:
  {
    const struct pdu_ipv6 *ipv6 = pdu;
    bsnprintf(detail, sizeof(detail), "(%I6/%u-%u AS%u)", ipv6->prefix, ipv6->prefix_len, ipv6->max_prefix_len, ipv6->asn);
    break;
  }

  case ROUTER_KEY:
    /* We don't support saving of Router Key PDUs yet */
    bsnprintf(detail, sizeof(detail), "(ignored)");
    break;

  case ERROR:
  {
    const struct pdu_error *err = pdu;
    bsnprintf(detail, sizeof(detail), "(type: %s)", str_pdu_error_type[err->error_code]);
    break;
  }

  default:
    *detail = '\0';
  }

  if (action == RPKI_RECV)
  {
    CACHE_TRACE(D_PACKETS, cache, "Received %s packet %s", str_type, detail);
  }
  else
  {
    CACHE_TRACE(D_PACKETS, cache, "Sending %s packet %s", str_type, detail);
  }

#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
  int seq = 0;
  for(const byte *c = pdu; c != pdu + header->len; c++)
  {
    if ((seq % 4) == 0)
      DBG("%2d: ", seq);

    DBG("  0x%02X %-3u", *c, *c);

    if ((++seq % 4) == 0)
      DBG("\n");
  }
  if ((seq % 4) != 0)
    DBG("\n");
#endif
}

static int
rpki_send_pdu(struct rpki_cache *cache, const void *pdu, const uint len)
{
  struct rpki_proto *p = cache->p;
  sock *sk = cache->tr_sock->sk;

  rpki_log_packet(cache, pdu, RPKI_SEND);

  if (sk->tbuf != sk->tpos)
  {
    RPKI_WARN(p, "Old packet overwritten in TX buffer");
  }

  if (len > sk->tbsize)
  {
    RPKI_WARN(p, "%u bytes is too much for send", len);
    ASSERT(0);
    return RPKI_ERROR;
  }

  memcpy(sk->tbuf, pdu, len);
  rpki_pdu_to_network_byte_order(sk->tbuf);

  if (!sk_send(sk, len))
  {
    DBG("Cannot send just the whole data. It will be sent using a call of tx_hook()");
  }

  return RPKI_SUCCESS;
}

/**
 * rpki_check_receive_packet - make a basic validation of received RPKI PDU header
 * @cache: cache connection instance
 * @pdu: RPKI PDU in network byte order
 *
 * This function checks protocol version, PDU type, version and size. If all is all right then
 * function returns |RPKI_SUCCESS| otherwise sends Error PDU and returns
 * |RPKI_ERROR|.
 */
static int
rpki_check_receive_packet(struct rpki_cache *cache, const void *pdu)
{
  struct rpki_proto *p = cache->p;
  int error = RPKI_SUCCESS;

  /* Header is in host byte order, retain original received pdu, in case we need to detach it to an error pdu */
  struct pdu_header header;
  memcpy(&header, pdu, sizeof(header));
  rpki_pdu_header_to_host_byte_order(&header);

  /*
   * Minimal and maximal allowed PDU size is treated in rpki_rx_hook() function.
   * @header.len corresponds to number of bytes of @pdu and
   * it is in range from RPKI_PDU_HEADER_LEN to RPKI_PDU_MAX_LEN bytes.
   */

  /* Do not handle error PDUs here, leave this task to rpki_handle_error_pdu() */
  if (header.ver != cache->version && header.type != ERROR)
  {
    /* If this is the first PDU we have received */
    if (cache->request_session_id)
    {
      if (header.type == SERIAL_NOTIFY)
      {
	/*
	 * The router MUST ignore any Serial Notify PDUs it might receive from
	 * the cache during this initial start-up period, regardless of the
	 * Protocol Version field in the Serial Notify PDU.
	 * (https://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-rfc6810-bis-07#section-7)
	 */
      }
      else if (cache->last_update == 0
		&& header.ver >= RPKI_MIN_VERSION
		&& header.ver <= RPKI_MAX_VERSION
		&& header.ver < cache->version)
      {
        CACHE_TRACE(D_EVENTS, cache, "Downgrade session to %s from %u to %u version", rpki_get_cache_ident(cache), cache->version, header.ver);
        cache->version = header.ver;
      }
      else
      {
        /* If this is not the first PDU we have received, something is wrong with
         * the server implementation -> Error */
	CACHE_TRACE(D_PACKETS, cache, "PDU with unsupported Protocol version received");
	rpki_send_error_pdu(cache, pdu, header.len, UNSUPPORTED_PROTOCOL_VER, NULL, 0);
	return RPKI_ERROR;
      }
    }
  }

  if ((header.type >= PDU_TYPE_MAX) || (header.ver == RPKI_VERSION_0 && header.type == ROUTER_KEY))
  {
    CACHE_DBG(cache, "Unsupported PDU type %u received", header.type);
    rpki_send_error_pdu(cache, pdu, header.len, UNSUPPORTED_PDU_TYPE, NULL, 0);
    return RPKI_ERROR;
  }

  if (header.len < min_pdu_size[header.type])
  {
    char txt[128];
    int txt_len = bsnprintf(txt, sizeof(txt), "Received %s packet with %d bytes, but expected at least %d bytes", str_pdu_type[header.type], header.len, min_pdu_size[header.type]);
    CACHE_TRACE(D_PACKETS, cache, "%s", txt);
    rpki_send_error_pdu(cache, pdu, header.len, CORRUPT_DATA, txt, txt_len + 1);
    return RPKI_ERROR;
  }

  return RPKI_SUCCESS;
}

static int
rpki_handle_error_pdu(struct rpki_cache *cache, const void *buf)
{
  const struct pdu_error *pdu = buf;

  const u32 len_err_txt = *((u32 *) (pdu->rest + pdu->len_enc_pdu));
  if (len_err_txt > 0)
  {
    size_t expected_len =
	sizeof(pdu->ver) +
	sizeof(pdu->type) +
	sizeof(pdu->error_code) +
	sizeof(pdu->len) +
	sizeof(pdu->len_enc_pdu) +
	pdu->len_enc_pdu +
	4 + len_err_txt;

    if (expected_len == pdu->len)
    {
      char txt[len_err_txt + 1];
      char *pdu_txt = (char *) pdu->rest + pdu->len_enc_pdu + 4;
      bsnprintf(txt, sizeof(txt), "%s", pdu_txt);
      CACHE_TRACE(D_PACKETS, cache, "Error PDU included the following error msg: '%s'", txt);
    }
    else
    {
      CACHE_TRACE(D_PACKETS, cache, "Unable print error description from Error PDU because of an incorrect length of packet");
    }
  }

  switch (pdu->error_code)
  {
  case CORRUPT_DATA:
  case INTERNAL_ERROR:
  case INVALID_REQUEST:
  case UNSUPPORTED_PDU_TYPE:
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;

  case NO_DATA_AVAIL:
    rpki_cache_change_state(cache, RPKI_CS_ERROR_NO_DATA_AVAIL);
    break;

  case UNSUPPORTED_PROTOCOL_VER:
    CACHE_TRACE(D_PACKETS, cache, "Client uses unsupported protocol version");
    if (pdu->ver <= RPKI_MAX_VERSION &&
	pdu->ver >= RPKI_MIN_VERSION &&
	pdu->ver < cache->version)
    {
      CACHE_TRACE(D_EVENTS, cache, "Downgrading from protocol version %d to version %d", cache->version, pdu->ver);
      cache->version = pdu->ver;
      rpki_cache_change_state(cache, RPKI_CS_FAST_RECONNECT);
    }
    else
    {
      CACHE_TRACE(D_PACKETS, cache, "Got UNSUPPORTED_PROTOCOL_VER error PDU with invalid values, " \
		  "current version: %d, PDU version: %d", cache->version, pdu->ver);
      rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    }
    break;

  default:
    CACHE_TRACE(D_PACKETS, cache, "Error unknown, server sent unsupported error code %u", pdu->error_code);
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;
  }

  return RPKI_SUCCESS;
}

static void
rpki_handle_serial_notify_pdu(struct rpki_cache *cache, const struct pdu_serial_notify *pdu)
{
  /* The router MUST ignore any Serial Notify PDUs it might receive from
   * the cache during this initial start-up period, regardless of the
   * Protocol Version field in the Serial Notify PDU.
   * (https://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-rfc6810-bis-07#section-7)
   */
  if (cache->request_session_id)
  {
    CACHE_TRACE(D_PACKETS, cache, "Ignore a Serial Notify packet during initial start-up period");
    return;
  }

  /* XXX Serial number should be compared using method RFC 1982 (3.2) */
  if (cache->serial_num != pdu->serial_num)
    rpki_cache_change_state(cache, RPKI_CS_SYNC_START);
}

static int
rpki_handle_cache_response_pdu(struct rpki_cache *cache, struct pdu_cache_response *pdu)
{
  if (cache->request_session_id)
  {
    if (cache->last_update != 0)
    {
      /*
       * This isn't the first sync and we already received records. This point
       * is after Reset Query and before importing new records from cache
       * server. We need to load new ones and kick out missing ones.  So start
       * a refresh cycle.
       */
      if (cache->roa4_channel)
	rt_refresh_begin(cache->roa4_channel->table, cache->roa4_channel);
      if (cache->roa6_channel)
	rt_refresh_begin(cache->roa6_channel->table, cache->roa6_channel);

      cache->refresh_channels = 1;
    }
    cache->session_id = pdu->session_id;
    cache->request_session_id = 0;
  }
  else
  {
    if (cache->session_id != pdu->session_id)
    {
      char txt[100];
      int txt_len = bsnprintf(txt, sizeof(txt), "Wrong session_id %u in Cache Response PDU", pdu->session_id);
      rpki_convert_pdu_back_to_network_byte_order(pdu);
      rpki_send_error_pdu(cache, pdu, ntohl(pdu->len), CORRUPT_DATA, txt, txt_len + 1);
      rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
      return RPKI_ERROR;
    }
  }

  rpki_cache_change_state(cache, RPKI_CS_SYNC_RUNNING);
  return RPKI_SUCCESS;
}

static net_addr_union *
rpki_prefix_pdu_2_net_addr(const void *pdu, net_addr_union *n)
{
  const enum pdu_type type = get_pdu_type(pdu);

  /*
   * Note that sizeof(net_addr_roa6) > sizeof(net_addr)
   * and thence we must use net_addr_union and not only net_addr
   */

  if (type == IPV4_PREFIX)
  {
    const struct pdu_ipv4 *ipv4 = pdu;
    n->roa4.type = NET_ROA4;
    n->roa4.length = sizeof(net_addr_roa4);
    n->roa4.prefix = ipv4->prefix;
    n->roa4.asn = ipv4->asn;
    n->roa4.pxlen = ipv4->prefix_len;
    n->roa4.max_pxlen = ipv4->max_prefix_len;
  }
  else if (type == IPV6_PREFIX)
  {
    const struct pdu_ipv6 *ipv6 = pdu;
    n->roa6.type = NET_ROA6;
    n->roa6.length = sizeof(net_addr_roa6);
    n->roa6.prefix = ipv6->prefix;
    n->roa6.asn = ipv6->asn;
    n->roa6.pxlen = ipv6->prefix_len;
    n->roa6.max_pxlen = ipv6->max_prefix_len;
  }

  return n;
}

static int
rpki_handle_prefix_pdu(struct rpki_cache *cache, void *pdu)
{
  struct channel *channel = NULL;

  const enum pdu_type type = get_pdu_type(pdu);
  ASSERT(type == IPV4_PREFIX || type == IPV6_PREFIX);

  if (type == IPV4_PREFIX)
    channel = cache->roa4_channel;
  if (type == IPV6_PREFIX)
    channel = cache->roa6_channel;

  net_addr_union addr = {};
  rpki_prefix_pdu_2_net_addr(pdu, &addr);

  if (!channel)
  {
    CACHE_TRACE(D_ROUTES, cache, "Skip %N, missing %s channel", &addr, (type == IPV4_PREFIX ? "roa4" : "roa6"), addr);
    return RPKI_ERROR;
  }

  cache->last_rx_prefix = now;

  switch ((((struct pdu_ipv4 *) pdu)->flags) & 0x1)
  {
  case RPKI_ADD_FLAG:
    rpki_table_add_roa(cache, channel, &addr);
    break;

  case RPKI_DELETE_FLAG:
    rpki_table_remove_roa(cache, channel, &addr);
    break;
  }

  return RPKI_SUCCESS;
}

static uint
rpki_check_interval(struct rpki_cache *cache, const char *(check_fn)(uint), uint interval)
{
  if (check_fn(interval))
  {
    RPKI_WARN(cache->p, "%s, received %u seconds", check_fn(interval), interval);
    return 0;
  }
  return 1;
}

static void
rpki_handle_end_of_data_pdu(struct rpki_cache *cache, void *pdu)
{
  const struct pdu_end_of_data_v1 *eod_pdu = pdu;
  const struct rpki_config *cf =  (void *) cache->p->p.cf;

  if (eod_pdu->session_id != cache->session_id)
  {
    char txt[67];
    int txt_len = bsnprintf(txt, sizeof(txt), "Received Session ID %u, but expected %u", eod_pdu->session_id, cache->session_id);
    CACHE_TRACE(D_EVENTS, cache, "%s", txt);
    rpki_convert_pdu_back_to_network_byte_order(pdu);
    rpki_send_error_pdu(cache, pdu, ntohl(eod_pdu->len), CORRUPT_DATA, txt, txt_len + 1);
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    return;
  }

  if (eod_pdu->ver == RPKI_VERSION_1)
  {
    if (!cf->keep_refresh_interval && rpki_check_interval(cache, rpki_check_refresh_interval, eod_pdu->refresh_interval))
      cache->refresh_interval = eod_pdu->refresh_interval;

    if (!cf->keep_retry_interval && rpki_check_interval(cache, rpki_check_retry_interval, eod_pdu->retry_interval))
          cache->retry_interval = eod_pdu->retry_interval;

    if (!cf->keep_expire_interval && rpki_check_interval(cache, rpki_check_expire_interval, eod_pdu->expire_interval))
      cache->expire_interval = eod_pdu->expire_interval;

    CACHE_TRACE(D_EVENTS, cache, "New interval values: "
		"refresh: %s%us, "
		"retry: %s%us, "
		"expire: %s%us",
		(cf->keep_refresh_interval ? "keeps " : ""), cache->refresh_interval,
		(cf->keep_retry_interval ? "keeps " : ""),   cache->retry_interval,
		(cf->keep_expire_interval ? "keeps " : ""),  cache->expire_interval);
  }

  if (cache->refresh_channels)
  {
    cache->refresh_channels = 0;
    if (cache->roa4_channel)
      rt_refresh_end(cache->roa4_channel->table, cache->roa4_channel);
    if (cache->roa6_channel)
      rt_refresh_end(cache->roa6_channel->table, cache->roa6_channel);
  }

  cache->last_update = now;
  cache->serial_num = eod_pdu->serial_num;
  rpki_cache_change_state(cache, RPKI_CS_ESTABLISHED);
}

/**
 * rpki_rx_packet - process a received RPKI PDU
 * @cache: RPKI connection instance
 * @pdu: a RPKI PDU in network byte order
 */
static void
rpki_rx_packet(struct rpki_cache *cache, void *pdu)
{
  struct rpki_proto *p = cache->p;
  enum pdu_type type = get_pdu_type(pdu);

  if (rpki_check_receive_packet(cache, pdu) == RPKI_ERROR)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    return;
  }

  rpki_pdu_header_to_host_byte_order(pdu);
  rpki_pdu_body_to_host_byte_order(pdu);
  rpki_log_packet(cache, pdu, RPKI_RECV);

  switch (type)
  {
  case RESET_QUERY:
  case SERIAL_QUERY:
    RPKI_WARN(p, "Received a %s packet that is destined for cache server", str_pdu_type[type]);
    break;

  case SERIAL_NOTIFY:
    /* This is a signal to synchronize with the cache server just now */
    rpki_handle_serial_notify_pdu(cache, pdu);
    break;

  case CACHE_RESPONSE:
    rpki_handle_cache_response_pdu(cache, pdu);
    break;

  case IPV4_PREFIX:
  case IPV6_PREFIX:
    rpki_handle_prefix_pdu(cache, pdu);
    break;

  case END_OF_DATA:
    rpki_handle_end_of_data_pdu(cache, pdu);
    break;

  case CACHE_RESET:
    /* Cache cannot provide an incremental update. */
    rpki_cache_change_state(cache, RPKI_CS_NO_INCR_UPDATE_AVAIL);
    break;

  case ERROR:
    rpki_handle_error_pdu(cache, pdu);
    break;

  case ROUTER_KEY:
    /* TODO: Implement Router Key PDU handling */
    break;

  default:
    CACHE_TRACE(D_PACKETS, cache, "Received unsupported type (%u)", type);
  };
}

int
rpki_rx_hook(struct birdsock *sk, int size)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;

  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;

  DBG("rx hook got %d bytes \n", size);

  while (end >= pkt_start + RPKI_PDU_HEADER_LEN)
  {
    struct pdu_header header;
    memcpy(&header, pkt_start, sizeof(header));
    rpki_pdu_header_to_host_byte_order(&header);

    if (header.len < RPKI_PDU_HEADER_LEN || header.len > RPKI_PDU_MAX_LEN)
    {
      RPKI_WARN(p, "Received invalid packet length %u. Purge the whole receiving buffer.", header.len);
      return 1; /* Purge recv buffer */
    }

    if (end < pkt_start + header.len)
      break;

    rpki_rx_packet(cache, pkt_start);

    /* It is possible that bird socket was freed/closed */
    if (p->p.proto_state == PS_DOWN || sk != cache->tr_sock->sk)
      return 0;

    pkt_start += header.len;
  }

  if (pkt_start != sk->rbuf)
  {
    CACHE_DBG(cache, "Move %u bytes of a memory at the start of buffer", end - pkt_start);
    memmove(sk->rbuf, pkt_start, end - pkt_start);
    sk->rpos = sk->rbuf + (end - pkt_start);
  }

  return 0; /* Not purge sk->rbuf */
}

void
rpki_err_hook(struct birdsock *sk, int error_num)
{
  struct rpki_cache *cache = sk->data;

  if (error_num)
  {
    /* sk->err may contains a SSH error description */
    if (sk->err)
      CACHE_TRACE(D_EVENTS, cache, "Lost connection: %s", sk->err);
    else
      CACHE_TRACE(D_EVENTS, cache, "Lost connection: %M", error_num);
  }
  else
  {
    CACHE_TRACE(D_EVENTS, cache, "The other side closed a connection");
  }


  rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
}

static int
rpki_fire_tx(struct rpki_cache *cache)
{
  sock *sk = cache->tr_sock->sk;

  uint bytes_to_send = sk->tpos - sk->tbuf;
  DBG("Sending %u bytes", bytes_to_send);
  return sk_send(sk, bytes_to_send);
}

void
rpki_tx_hook(sock *sk)
{
  struct rpki_cache *cache = sk->data;

  while (rpki_fire_tx(cache) > 0)
    ;
}

void
rpki_connected_hook(sock *sk)
{
  struct rpki_cache *cache = sk->data;

  CACHE_TRACE(D_EVENTS, cache, "Connected");
  proto_notify_state(&cache->p->p, PS_UP);

  sk->rx_hook = rpki_rx_hook;
  sk->tx_hook = rpki_tx_hook;

  rpki_cache_change_state(cache, RPKI_CS_SYNC_START);
}

/**
 * rpki_send_error_pdu - send RPKI Error PDU
 * @cache: RPKI connection instance
 * @erroneous_pdu: optional network byte-order PDU that invokes Error by us or NULL
 * @err_pdu_len: length of @erroneous_pdu
 * @error_code: PDU Error type
 * @text: optional description text of error or NULL
 * @text_len: length of @text
 *
 * This function prepares Error PDU and sends it to a cache server.
 */
static int
rpki_send_error_pdu(struct rpki_cache *cache, const void *erroneous_pdu, const u32 err_pdu_len, const enum pdu_error_type error_code, const char *text, const u32 text_len)
{
  /* Don't send errors for erroneous error PDUs */
  if (err_pdu_len >= 2)
  {
    if (get_pdu_type(erroneous_pdu) == ERROR)
      return RPKI_SUCCESS;
  }

  u32 pdu_size = 16 + err_pdu_len + text_len;
  char pdu[pdu_size];
  memset(pdu, sizeof(pdu), 0);

  struct pdu_error *e = (void *) pdu;
  e->ver = cache->version;
  e->type = ERROR;
  e->error_code = error_code;
  e->len = pdu_size;

  e->len_enc_pdu = err_pdu_len;
  if (err_pdu_len > 0)
    memcpy(e->rest, erroneous_pdu, err_pdu_len);

  *((u32 *)(e->rest + err_pdu_len)) = text_len;
  if (text_len > 0)
    memcpy(e->rest + err_pdu_len + 4, text, text_len);

  return rpki_send_pdu(cache, pdu, pdu_size);
}

int
rpki_send_serial_query(struct rpki_cache *cache)
{
  struct pdu_serial_query pdu = {
      .ver = cache->version,
      .type = SERIAL_QUERY,
      .session_id = cache->session_id,
      .len = sizeof(pdu),
      .serial_num = cache->serial_num
  };

  if (rpki_send_pdu(cache, &pdu, sizeof(pdu)) != RPKI_SUCCESS)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return RPKI_ERROR;
  }

  return RPKI_SUCCESS;
}

int
rpki_send_reset_query(struct rpki_cache *cache)
{
  struct pdu_reset_query pdu = {
      .ver = cache->version,
      .type = RESET_QUERY,
      .len = 8,
  };

  if (rpki_send_pdu(cache, &pdu, sizeof(pdu)) != RPKI_SUCCESS)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return RPKI_ERROR;
  }

  return RPKI_SUCCESS;
}
