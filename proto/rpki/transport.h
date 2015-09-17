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

/*
 * The RPKI transport sockets implement the communication channel
 * (e.g., SSH, TCP, TCP-AO) between an RPKI server and client.
 *
 * Before using the transport socket, a tr_socket must be
 * initialized based on a protocol-dependent init function (e.g.,
 * rpki_tr_tcp_init()).
 *
 * The rpki_tr_* functions call the corresponding function pointers, which are
 * passed in the rpki_tr_sock struct, and forward the remaining arguments.
 */

#ifndef _BIRD_RPKI_TRANSPORT_H_
#define _BIRD_RPKI_TRANSPORT_H_

#include <time.h>

/* Types of supported transports */
enum rpki_tr_type {
  RPKI_TR_TCP,				/* Unprotected transport over TCP */
  RPKI_TR_SSH,				/* Protected transport by SSHv2 connection */
};

/* Common configure struct for transports */
struct rpki_tr_config {
  enum rpki_tr_type type;
};

/* The return values for rpki_tr_ functions */
enum tr_rtvals {
  TR_SUCCESS = 0,			/* Operation was successfull */
  TR_ERROR = -1,			/* Error occured */
  TR_WOULDBLOCK = -2,			/* No data is available on the socket */
  TR_INTR = -3,				/* Call was interrupted from a signal */
  TR_CLOSED = -4			/* Connection closed */
};

/* A transport socket structure */
struct rpki_tr_sock {
  void *data;				/* Technology specific data */
  sock *sk;				/* Standard BIRD socket */
  struct rpki_cache *cache;		/* Cache server */
  int (*open_fp)(struct rpki_tr_sock *); /* Pointer to a function that establishes the socket connection */
  void (*close_fp)(struct rpki_tr_sock *); /* Pointer to a function that close and frees all memory allocated with this socket */
  const char *(*ident_fp)(struct rpki_tr_sock *); /* Pointer to a function that returns an identifier for the socket endpoint */
};

int rpki_tr_open(struct rpki_tr_sock *tr);
void rpki_tr_close(struct rpki_tr_sock *tr);
const char *rpki_tr_ident(struct rpki_tr_sock *tr);

#endif
