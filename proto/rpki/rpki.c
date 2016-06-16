/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	Using RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: RPKI To Router (RPKI-RTR)
 *
 * The RPKI RTR protocol is implemented in several files: |rpki.c| containing
 * the routes handling, protocol logic, timer events, cache connection,
 * reconfiguration, configuration and protocol glue with BIRD core, |packets.c|
 * containing the RPKI packets handling and finally all transports files:
 * |transport.c|, |tcp_transport.c| and |ssh_transport.c|.
 *
 * |transport.c| is a middle layer and interface for each specific transport.
 * There is supported an unprotected TCP transport and an encrypted SSH
 * transport. The SSH transport requires LibSSH library. LibSSH is loading
 * dynamically using |dlopen()| function. SSH support is integrated in
 * |sysdep/unix/io.c|. Each transport must implement an initialization, open and
 * identification function. That's all.
 *
 * The implementation is based on the RTRlib (http://rpki.realmv6.org/). The
 * BIRD takes over files |packets.c|, |rtr.c| (inside |rpki.c|), |transport.c|,
 * |tcp_transport.c| and |ssh_transport.c| from RTRlib.
 *
 * A RPKI RTR connection is described by a structure &rpki_cache. The main
 * logic is located in |rpki_cache_change_state()| function. There is a state
 * automat. The standard starting state flow looks like |Down| ~> |Connecting| ~>
 * |Sync-Start| ~> |Sync-Running| ~> |Established|. Allowed transitions are
 * defined by function |rpki_is_allowed_transition_cache_state()|.
 *
 * The RPKI-RTR protocol (RFC 6810) defines configurable refresh, retry and
 * expire intervals. For maintaining a connection are used timer events that
 * are scheduled by |rpki_schedule_next_refresh()|,
 * |rpki_schedule_next_retry()| and |rpki_schedule_next_expire()| functions.
 * A Retry timers event is active only after
 *
 * A reconfiguration of cache connection may works well without flushing all
 * routes and loading again.
 *
 * Supported standards:
 * - RFC 6810 - the main RPKI-RTR standard
 * - draft-ietf-sidr-rpki-rtr-rfc6810-bis-07 - a successor of RFC 6810
 *   - Explicit timing parameters
 *   - Protocol version number negotiation
 */

#include <stdlib.h>
#include <netdb.h>

#undef LOCAL_DEBUG

#include "rpki.h"
#include "lib/string.h"
#include "nest/cli.h"

/* Return values for reconfiguration functions */
#define NEED_TO_RESTART 	0
#define SUCCESSFUL_RECONF 	1

static int rpki_open_connection(struct rpki_cache *cache);
static void rpki_close_connection(struct rpki_cache *cache);


/*
 * 	Routes handling
 */

void
rpki_table_add_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr)
{
  struct rpki_proto *p = cache->p;

  net *n = net_get(channel->table, &pfxr->n);

  rta a0 = {
      .src = p->p.main_source,
      .source = RTS_RPKI,
      .scope = SCOPE_UNIVERSE,
      .cast = RTC_UNICAST,
      .dest = RTD_BLACKHOLE,
  };

  rta *a = rta_lookup(&a0);
  rte *e = rte_get_temp(a);

  e->net = n;
  e->pflags = 0;

  rte_update2(channel, &pfxr->n, e, a0.src);
}

void
rpki_table_remove_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr)
{
  struct rpki_proto *p = cache->p;
  rte_update2(channel, &pfxr->n, NULL, p->p.main_source);
}

static void
rpki_table_remove_all(struct rpki_cache *cache)
{
  CACHE_TRACE(D_ROUTES, cache, "Removing all routes");

  if (cache->roa4_channel && cache->roa4_channel->channel_state != CS_DOWN)
    channel_close(cache->roa4_channel);

  if (cache->roa6_channel && cache->roa6_channel->channel_state != CS_DOWN)
    channel_close(cache->roa6_channel);
}

static void
rpki_purge_records_if_outdated(struct rpki_cache *cache)
{
  if (cache->last_update == 0)
    return;

  if ((cache->last_update + cache->expire_interval) < now)
  {
    CACHE_TRACE(D_EVENTS, cache, "All routes expired");
    rpki_table_remove_all(cache);
    cache->request_session_id = 1;
    cache->serial_num = 0;
    cache->last_update = 0;
  }
  else
  {
    CACHE_DBG(cache, "No outdated records, remains %d seconds to become obsolete", (int)cache->expire_interval - (int)(now - cache->last_update));
  }
}


/*
 *	RPKI Protocol Logic
 */

static const char *str_cache_states[] = {
    [RPKI_CS_CONNECTING] = "Connecting",
    [RPKI_CS_ESTABLISHED] = "Established",
    [RPKI_CS_RESET] = "Reseting",
    [RPKI_CS_SYNC_START] = "Sync-Start",
    [RPKI_CS_SYNC_RUNNING] = "Sync-Running",
    [RPKI_CS_FAST_RECONNECT] = "Fast-Reconnect",
    [RPKI_CS_NO_INCR_UPDATE_AVAIL] = "No-Increment-Update-Available",
    [RPKI_CS_ERROR_NO_DATA_AVAIL] = "Cache-Error-No-Data-Available",
    [RPKI_CS_ERROR_FATAL] = "Fatal-Protocol-Error",
    [RPKI_CS_ERROR_TRANSPORT] = "Transport-Error",
    [RPKI_CS_SHUTDOWN] = "Down"
};

/**
 * rpki_cache_state_to_str - give a text representation of cache state
 * @state: A cache state
 *
 * The function converts logic cache state into string.
 */
static const char *
rpki_cache_state_to_str(enum rpki_cache_state state)
{
  return str_cache_states[state];
}

/**
 * rpki_start_cache - kick up the connection to cache server
 *
 * This function is the high level method to kick up the connection to cache server.
 */
static void
rpki_start_cache(struct rpki_cache *cache)
{
  rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
}

/**
 * rpki_is_allowed_transition_cache_state - validate cache state transition
 *
 * This function defines and validates state transitions of cache.
 * It returns |1| for valid transition or zero for invalid transition.
 * It's good for the development.
 */
static int
rpki_is_allowed_transition_cache_state(const enum rpki_cache_state old, const enum rpki_cache_state new)
{
  switch (new)
  {
  case RPKI_CS_CONNECTING: 	return old == RPKI_CS_SHUTDOWN || old == RPKI_CS_ERROR_TRANSPORT || old == RPKI_CS_FAST_RECONNECT;
  case RPKI_CS_ESTABLISHED: 	return old == RPKI_CS_SYNC_RUNNING;
  case RPKI_CS_RESET:		return old == RPKI_CS_ERROR_NO_DATA_AVAIL || old == RPKI_CS_NO_INCR_UPDATE_AVAIL;
  case RPKI_CS_SYNC_START:	return old == RPKI_CS_RESET || old == RPKI_CS_CONNECTING || old == RPKI_CS_ESTABLISHED;
  case RPKI_CS_SYNC_RUNNING:	return old == RPKI_CS_SYNC_START;
  case RPKI_CS_FAST_RECONNECT:	return old == RPKI_CS_ESTABLISHED || old == RPKI_CS_SYNC_START || old == RPKI_CS_SYNC_RUNNING;
  case RPKI_CS_NO_INCR_UPDATE_AVAIL:	return old == RPKI_CS_SYNC_START;
  case RPKI_CS_ERROR_NO_DATA_AVAIL:	return old == RPKI_CS_SYNC_START;
  case RPKI_CS_ERROR_FATAL:	return 1;
  case RPKI_CS_ERROR_TRANSPORT:	return 1;
  case RPKI_CS_SHUTDOWN:	return 1;
  }
  return 0;
}

/**
 * rpki_cache_change_state - check and change cache state
 * @cache: RPKI cache instance
 * @new_state: suggested new state
 *
 * This function makes transitions between internal states.
 * It represents the core of logic management of RPKI protocol.
 * Cannot transit into the same state as cache is in already.
 * Checkout the |rpki_is_allowed_transition_cache_state| function for imagine of possible transitions.
 */
void
rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state)
{
  const enum rpki_cache_state old_state = cache->state;

  if (old_state == new_state)
    return;

  if (!rpki_is_allowed_transition_cache_state(old_state, new_state))
  {
    CACHE_DBG(cache, "Change state %s -> %s is not allowed", rpki_cache_state_to_str(old_state), rpki_cache_state_to_str(new_state));
    ASSERT(0);
    return;
  }

  CACHE_TRACE(D_EVENTS, cache, "Change state %s -> %s", rpki_cache_state_to_str(old_state), rpki_cache_state_to_str(new_state));
  cache->state = new_state;

  switch (new_state)
  {
  case RPKI_CS_CONNECTING:
  {
    sock *sk = cache->tr_sock->sk;

    if (sk == NULL || sk->fd < 0)
      rpki_open_connection(cache);
    else
      rpki_cache_change_state(cache, RPKI_CS_SYNC_START);

    break;
  }

  case RPKI_CS_ESTABLISHED:
    break;

  case RPKI_CS_RESET:
    /* Resetting cache connection. */
    cache->request_session_id = 1;
    cache->serial_num = 0;
    rpki_cache_change_state(cache, RPKI_CS_SYNC_START);
    break;

  case RPKI_CS_SYNC_START:
    /* Requesting for receive validation records from the cache server. */
    if (cache->request_session_id)
    {
      /* Send request for Session ID */
      if (rpki_send_reset_query(cache) != RPKI_SUCCESS)
	rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    }
    else
    {
      /* We have already a session_id. So send a Serial Query and start to sync */
      if (rpki_send_serial_query(cache) != RPKI_SUCCESS)
	rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    }
    break;

  case RPKI_CS_SYNC_RUNNING:
    /* The state between Cache Response and End of Data. Only waiting for
     * receiving all IP Prefix PDUs and finally a End of Data PDU. */
    break;

  case RPKI_CS_NO_INCR_UPDATE_AVAIL:
    /* Server was unable to answer the last Serial Query and sent Cache Reset. */
    rpki_cache_change_state(cache, RPKI_CS_RESET);
    break;

  case RPKI_CS_ERROR_NO_DATA_AVAIL:
    /* No validation records are available on the cache server. */
    rpki_cache_change_state(cache, RPKI_CS_RESET);
    break;

  case RPKI_CS_ERROR_FATAL:
    /* Fatal protocol error occurred. */
    cache->request_session_id = 1;
    cache->serial_num = 0;
    cache->last_update = 0;
    rpki_table_remove_all(cache);
    /* Fall through */

  case RPKI_CS_ERROR_TRANSPORT:
    /* Error on the transport socket occurred. */
    rpki_close_connection(cache);
    rpki_schedule_next_retry(cache);
    break;

  case RPKI_CS_FAST_RECONNECT:
    /* Reconnect without any waiting period */
    rpki_close_connection(cache);
    rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
    break;

  case RPKI_CS_SHUTDOWN:
    /* The connection to cache has to stop */
    rpki_close_connection(cache);
    cache->request_session_id = 1;
    cache->serial_num = 0;
    cache->last_update = 0;
    rpki_table_remove_all(cache);
    break;
  };
}


/*
 * 	RPKI Timer Events
 */

void
rpki_schedule_next_refresh(struct rpki_cache *cache)
{
  uint time_to_wait = cache->refresh_interval;

  CACHE_DBG(cache, "Scheduling next refresh after %u seconds", time_to_wait);
  tm_start(cache->refresh_timer, time_to_wait);
}

void
rpki_schedule_next_retry(struct rpki_cache *cache)
{
  uint time_to_wait = cache->retry_interval;

  CACHE_DBG(cache, "Scheduling next retry after %u seconds", time_to_wait);
  tm_start(cache->retry_timer, time_to_wait);
}

void
rpki_schedule_next_expire_check(struct rpki_cache *cache)
{
  /* A minimum time to wait is 1 second */
  uint time_to_wait = MAX(((int)cache->expire_interval - (int)(now - cache->last_update)), 1);

  CACHE_DBG(cache, "Scheduling next expiration check after %u seconds", time_to_wait);
  tm_start(cache->expire_timer, time_to_wait);
}

/**
 * rpki_refresh_hook - control a scheduling of downloading data from cache server
 *
 * This function is periodically called during &ESTABLISHED or &SYNC* state cache connection.
 * The first refresh schedule is invoked after receiving a |End of Data| PDU and
 * has run by some &ERROR is occurred.
 */
static void
rpki_refresh_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
    rpki_cache_change_state(cache, RPKI_CS_SYNC_START);
    break;

  case RPKI_CS_SYNC_START:
    /* We sent Serial/Reset Query in last refresh hook call
     * and didn't receive Cache Response yet. It looks like
     * troubles with network. */
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    break;

  default:
    break;
  }

  if (cache->state != RPKI_CS_SHUTDOWN && cache->state != RPKI_CS_ERROR_TRANSPORT)
    rpki_schedule_next_refresh(cache);
  else
    CACHE_DBG(cache, "Stop refreshing");
}

/**
 * rpki_retry_hook - control a scheduling of retrying connection to cache server
 *
 * This function is periodically called during &ERROR* state cache connection.
 * The first retry schedule is invoked after any &ERROR* state occurred and
 * ends by reaching of &ESTABLISHED state again.
 */
static void
rpki_retry_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
  case RPKI_CS_CONNECTING:
  case RPKI_CS_SYNC_START:
  case RPKI_CS_SYNC_RUNNING:
  case RPKI_CS_SHUTDOWN:
    break;

  default:
    rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
    break;
  }

  if (cache->state != RPKI_CS_ESTABLISHED)
    rpki_schedule_next_retry(cache);
  else
    CACHE_DBG(cache, "Stop retrying connection");
}

/**
 * rpki_expire_hook - control a expiration of ROA entries
 *
 * This function is called after receiving each |End of Data| PDU.
 * The actual wait interval is calculated dynamically.
 * The expiration timer is destroyed after purging all ROA entries from tables.
 */
static void
rpki_expire_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, ""); /* Show name of function */

  rpki_purge_records_if_outdated(cache);

  if (cache->last_update)
    rpki_schedule_next_expire_check(cache);
  else
    CACHE_DBG(cache, "Stop expiration check");
}

/**
 * rpki_check_refresh_interval - check validity of refresh interval value
 * @seconds: suggested value
 *
 * This function validates value and should return |NULL|.
 * If the check doesn't pass then returns error message.
 */
const char *
rpki_check_refresh_interval(uint seconds)
{
  if (seconds < 1)
    return "Minimum allowed refresh interval is 1 second";
  if (seconds > 86400)
    return "Maximum allowed refresh interval is 86400 seconds";
  return NULL;
}

/**
 * rpki_check_retry_interval - check validity of retry interval value
 * @seconds: suggested value
 *
 * This function validates value and should return |NULL|.
 * If the check doesn't pass then returns error message.
 */
const char *
rpki_check_retry_interval(uint seconds)
{
  if (seconds < 1)
    return "Minimum allowed retry interval is 1 second";
  if (seconds > 7200)
    return "Maximum allowed retry interval is 7200 seconds";
  return NULL;
}

/**
 * rpki_check_expire_interval - check validity of expire interval value
 * @seconds: suggested value
 *
 * This function validates value and should return |NULL|.
 * If the check doesn't pass then returns error message.
 */
const char *
rpki_check_expire_interval(uint seconds)
{
  if (seconds < 600)
    return "Minimum allowed expire interval is 600 seconds";
  if (seconds > 172800)
    return "Maximum allowed expire interval is 172800 seconds";
  return NULL;
}


/*
 * 	RPKI Cache
 */

static struct rpki_cache *
rpki_init_cache(struct rpki_proto *p, struct rpki_config *cf)
{
  pool *pool = rp_new(p->p.pool, cf->hostname);

  struct rpki_cache *cache = mb_allocz(pool, sizeof(struct rpki_cache));

  cache->pool = pool;
  cache->p = p;

  proto_configure_channel(&p->p, &cache->roa4_channel, proto_cf_find_channel(p->p.cf, NET_ROA4));
  proto_configure_channel(&p->p, &cache->roa6_channel, proto_cf_find_channel(p->p.cf, NET_ROA6));

  cache->state = RPKI_CS_SHUTDOWN;
  cache->request_session_id = 1;
  cache->version = RPKI_MAX_VERSION;

  cache->refresh_interval = cf->refresh_interval;
  cache->retry_interval = cf->retry_interval;
  cache->expire_interval = cf->expire_interval;
  cache->retry_timer = tm_new_set(pool, &rpki_retry_hook, cache, 0, 0);
  cache->refresh_timer = tm_new_set(pool, &rpki_refresh_hook, cache, 0, 0);
  cache->expire_timer = tm_new_set(pool, &rpki_expire_hook, cache, 0, 0);

  cache->tr_sock = mb_allocz(pool, sizeof(struct rpki_tr_sock));
  cache->tr_sock->cache = cache;

  switch (cf->tr_config.type)
  {
  case RPKI_TR_TCP: rpki_tr_tcp_init(cache->tr_sock); break;
  case RPKI_TR_SSH: rpki_tr_ssh_init(cache->tr_sock); break;
  };

  CACHE_TRACE(D_EVENTS, cache, "Created");

  return cache;
}

/**
 * rpki_get_cache_ident - give a text representation of remote cache name
 *
 * The function converts cache connection into string.
 */
const char *
rpki_get_cache_ident(struct rpki_cache *cache)
{
  return rpki_tr_ident(cache->tr_sock);
}

static int
rpki_open_connection(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Opening a connection");

  if (rpki_tr_open(cache->tr_sock) == RPKI_TR_ERROR)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return RPKI_TR_ERROR;
  }

  return RPKI_TR_SUCCESS;
}

static void
rpki_close_connection(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Closing a connection");
  rpki_tr_close(cache->tr_sock);
  proto_notify_state(&cache->p->p, PS_START);
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *p = (void *) P;
  p->cache = NULL;

  /* protocol memory pool will be automatically freed */
  return PS_DOWN;
}

static void
rpki_free_cache(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;

  rpki_table_remove_all(cache);

  CACHE_TRACE(D_EVENTS, p->cache, "Destroyed");
  rfree(cache->pool);
  p->cache = NULL;
}


/*
 * 	RPKI Reconfiguration
 */

static void
rpki_replace_cache(struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  struct rpki_proto *p = cache->p;

  rpki_free_cache(cache);

  p->cache = rpki_init_cache(p, new);
  rpki_start_cache(p->cache);
}

static void
rpki_try_fast_reconnect(struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  if (cache->state == RPKI_CS_ESTABLISHED)
    rpki_cache_change_state(cache, RPKI_CS_FAST_RECONNECT);
  else
    rpki_replace_cache(cache, old, new);
}

/**
 * rpki_reconfigure_cache - a cache reconfiguration
 * @p: RPKI protocol instance
 * @cache: a cache connection
 * @new: new RPKI configuration
 * @old: old RPKI configuration
 *
 * This function reconfigures existing single cache connection with new existing configuration.
 * Returns |NEED_TO_RESTART| or |SUCCESSFUL_RECONF|.
 */
static int
rpki_reconfigure_cache(struct rpki_proto *p, struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  u8 try_fast_reconnect = 0;

  if (!proto_configure_channel(&p->p, &cache->roa4_channel, proto_cf_find_channel(p->p.cf, NET_ROA4)) ||
      !proto_configure_channel(&p->p, &cache->roa6_channel, proto_cf_find_channel(p->p.cf, NET_ROA6)))
  {
    CACHE_TRACE(D_EVENTS, cache, "Channels changed");
    return NEED_TO_RESTART;
  }

  if (strcmp(old->hostname, new->hostname) != 0)
  {
    CACHE_TRACE(D_EVENTS, cache, "Remote cache server address changed to %s", new->hostname);
    goto hard_cache_replace;
  }

  if (old->port != new->port)
  {
    CACHE_TRACE(D_EVENTS, cache, "Remote cache server port changed to %u", new->port);
    goto hard_cache_replace;
  }

  if (old->tr_config.type != new->tr_config.type)
  {
    CACHE_TRACE(D_EVENTS, cache, "Transport type changed");
    goto hard_cache_replace;
  }
  else if ((old->tr_config.type == new->tr_config.type) && (new->tr_config.type == RPKI_TR_SSH))
  {
    struct rpki_tr_ssh_config *ssh_old = (void *) old->tr_config.spec;
    struct rpki_tr_ssh_config *ssh_new = (void *) new->tr_config.spec;
    if ((strcmp(ssh_old->bird_private_key, ssh_new->bird_private_key) != 0) ||
	(strcmp(ssh_old->cache_public_key, ssh_new->cache_public_key) != 0) ||
	(strcmp(ssh_old->user, ssh_new->user) != 0))
    {
      CACHE_TRACE(D_EVENTS, cache, "Settings of SSH transport encryption changed");
      try_fast_reconnect = 1;
    }
  }

#define TEST_INTERVAL(name, Name) 						\
    if (cache->name##_interval != new->name##_interval ||			\
	old->keep_##name##_interval != new->keep_##name##_interval) 		\
    { 										\
      cache->name##_interval = new->name##_interval;				\
      CACHE_TRACE(D_EVENTS, cache, #Name " interval changed to %u seconds %s", cache->name##_interval, (new->keep_##name##_interval ? "and keep it" : "")); \
      try_fast_reconnect = 1; 							\
    }
  TEST_INTERVAL(refresh, Refresh);
  TEST_INTERVAL(retry, Retry);
  TEST_INTERVAL(expire, Expire);
#undef TEST_INTERVAL

  if (try_fast_reconnect)
    rpki_try_fast_reconnect(cache, new, old);

  return SUCCESSFUL_RECONF;

 hard_cache_replace:
  rpki_replace_cache(cache, new, old);
  return SUCCESSFUL_RECONF;
}

/**
 * rpki_reconfigure_proto - a protocol reconfiguration
 *
 * This function reconfigures a protocol.
 * Returns |NEED_TO_RESTART| or |SUCCESSFUL_RECONF|.
 */
static int
rpki_reconfigure_proto(struct rpki_proto *p, struct rpki_config *new_cf, struct rpki_config *old_cf)
{
  u8 new = new_cf && new_cf->hostname;
  u8 old = old_cf && old_cf->hostname;
  struct rpki_cache *cache = p->cache;

  if (new && !old)
  {
    p->cache = rpki_init_cache(p, new_cf);
    rpki_start_cache(p->cache);
  }
  else if (!new && old && cache)
    rpki_free_cache(cache);
  else if (new && old && cache)
    return rpki_reconfigure_cache(p, cache, new_cf, old_cf);

  return SUCCESSFUL_RECONF;
}

/**
 * rpki_reconfigure - a protocol reconfiguration hook
 * @P: a protocol instance
 * @CF: a new protocol configuration
 *
 * This function is wrap function for |rpki_reconfigure_proto()|.
 * It sets new protocol configuration into a protocol structure.
 * If the protocol needs to be restarted then there is set an old configuration back.
 * Returns |NEED_TO_RESTART| or |SUCCESSFUL_RECONF|.
 */
static int
rpki_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct rpki_proto *p = (void *) P;
  struct rpki_config *new = (void *) CF;
  struct rpki_config *old = (void *) p->p.cf;

  P->cf = CF;
  if (rpki_reconfigure_proto(p, new, old) == SUCCESSFUL_RECONF)
    return SUCCESSFUL_RECONF;

  P->cf = (void *) old;
  return NEED_TO_RESTART;
}


/*
 * 	RPKI Protocol Glue
 */

static struct proto *
rpki_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);

  return P;
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *p = (void *) P;
  struct rpki_config *cf = (void *) P->cf;

  rpki_reconfigure_proto(p, cf, NULL);

  return PS_START;
}

static void
rpki_get_status(struct proto *P, byte *buf)
{
  struct rpki_proto *p = (struct rpki_proto *) P;

  if (P->proto_state == PS_DOWN)
  {
    *buf = 0;
    return;
  }

  if (p->cache)
    bsprintf(buf, "%s", rpki_cache_state_to_str(p->cache->state));
  else
    bsprintf(buf, "No cache server configured");
}

static void
rpki_show_proto_info_timer(const char *name, uint num, timer *t)
{
  if (t->expires)
    cli_msg(-1006, "  %-17s %us (remains %us)", name, num, tm_remains(t));
  else
    cli_msg(-1006, "  %-17s ---", name);
}

static void
rpki_show_proto_info(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *cf = (void *) p->p.cf;
  struct rpki_cache *cache = p->cache;

  if (cache)
  {
    const char *transport_name = "---";

    switch (cf->tr_config.type)
    {
    case RPKI_TR_SSH: transport_name = "SSHv2"; break;
    case RPKI_TR_TCP: transport_name = "Unprotected over TCP"; break;
    };

    cli_msg(-1006, "  Cache server:     %s", rpki_get_cache_ident(cache));
    cli_msg(-1006, "  Status:           %s", rpki_cache_state_to_str(cache->state));
    cli_msg(-1006, "  Transport:        %s", transport_name);
    cli_msg(-1006, "  Protocol version: %u", cache->version);

    if (cache->request_session_id)
      cli_msg(-1006, "  Session ID:       ---");
    else
      cli_msg(-1006, "  Session ID:       %u", cache->session_id);

    if (cache->last_update)
    {
      cli_msg(-1006, "  Serial number:    %u", cache->serial_num);
      cli_msg(-1006, "  Last update:      before %us", now - cache->last_update);
    }
    else
    {
      cli_msg(-1006, "  Serial number:    ---");
      cli_msg(-1006, "  Last update:      ---");
    }

    rpki_show_proto_info_timer("Refresh interval:", cache->refresh_interval, cache->refresh_timer);
    rpki_show_proto_info_timer("Retry interval:", cache->retry_interval, cache->retry_timer);
    rpki_show_proto_info_timer("Expire interval:", cache->expire_interval, cache->expire_timer);

    if (cache->roa4_channel)
      channel_show_info(cache->roa4_channel);
    else
      cli_msg(-1006, "  No roa4 channel");

    if (cache->roa6_channel)
      channel_show_info(cache->roa6_channel);
    else
      cli_msg(-1006, "  No roa6 channel");
  }
}


/*
 * 	RPKI Protocol Configuration
 */

/**
 * rpki_check_config - check and complete configuration of RPKI protocol
 * @cf: RPKI configuration
 *
 * This function is called at the end of parsing RPKI protocol configuration.
 */
void
rpki_check_config(struct rpki_config *cf)
{
  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;

  if (ipa_zero(cf->ip) && cf->hostname == NULL)
    cf_error("Address or hostname of remote cache server must be set");

  if (cf->tr_config.spec == NULL)
  {
    cf->tr_config.spec = cfg_allocz(sizeof(struct rpki_tr_tcp_config));
    cf->tr_config.type = RPKI_TR_TCP;
  }

  if (cf->port == 0)
  {
    switch (cf->tr_config.type)
    {
    case RPKI_SSH_PORT:
      cf->port = RPKI_SSH_PORT;
      break;
    default:
      cf->port = RPKI_TCP_PORT;
    }
  }
}

static void
rpki_postconfig(struct proto_config *CF)
{
  /* Define default channel */
  if (EMPTY_LIST(CF->channels))
    channel_config_new(NULL, CF->net_type, CF);
}

static void
rpki_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Just a shallow copy */
}

struct protocol proto_rpki = {
    .name = 		"RPKI",
    .template = 	"rpki%d",
    .preference = 	DEF_PREF_RPKI,
    .proto_size = 	sizeof(struct rpki_proto),
    .config_size =	sizeof(struct rpki_config),
    .init = 		rpki_init,
    .start = 		rpki_start,
    .postconfig = 	rpki_postconfig,
    .channel_mask =	(NB_ROA4 | NB_ROA6),
    .show_proto_info =	rpki_show_proto_info,
    .shutdown = 	rpki_shutdown,
    .copy_config = 	rpki_copy_config,
    .reconfigure = 	rpki_reconfigure,
    .get_status = 	rpki_get_status,
};
