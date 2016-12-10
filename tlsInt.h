/*
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 *
 * TLS (aka SSL) Channel - can be layered on any bi-directional
 * Tcl_Channel (Note: Requires Trf Core Patch)
 *
 * This was built from scratch based upon observation of OpenSSL 0.9.2B
 *
 * Addition credit is due for Andreas Kupries (a.kupries@westend.com), for
 * providing the Tcl_ReplaceChannel mechanism and working closely with me
 * to enhance it to support full fileevent semantics.
 *
 * Also work done by the follow people provided the impetus to do this "right":-
 *	tclSSL (Colin McCormack, Shared Technology)
 *	SSLtcl (Peter Antman)
 *
 */
#ifndef _TLSINT_H
#define _TLSINT_H

#include "tls.h"
#include <errno.h>
#include <string.h>

#ifdef __WIN32__
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h> /* OpenSSL needs this on Windows */
#endif

/* Handle tcl8.3->tcl8.4 CONST changes */
#ifndef CONST84
#define CONST84
#endif

#ifdef NO_PATENTS
#  define NO_IDEA
#  define NO_RC2
#  define NO_RC4
#  define NO_RC5
#  define NO_RSA
#  ifndef NO_SSL2
#    define NO_SSL2
#  endif
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

/*
 * Determine if we should use the pre-OpenSSL 1.1.0 API
 */
#undef TCLTLS_OPENSSL_PRE_1_1
#if (defined(LIBRESSL_VERSION_NUMBER)) || OPENSSL_VERSION_NUMBER < 0x10100000L
#  define TCLTLS_OPENSSL_PRE_1_1_API 1
#endif

#ifndef ECONNABORTED
#define ECONNABORTED	130	/* Software caused connection abort */
#endif
#ifndef ECONNRESET
#define ECONNRESET	131	/* Connection reset by peer */
#endif

#ifdef TCLEXT_TCLTLS_DEBUG
#define dprintf(...) { fprintf(stderr, "%s:%i:", __func__, __LINE__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define dprintf(...) if (0) { fprintf(stderr, __VA_ARGS__); }
#endif

#define TCLTLS_SSL_ERROR(ssl,err) ((char*)ERR_reason_error_string((unsigned long)SSL_get_error((ssl),(err))))
/*
 * OpenSSL BIO Routines
 */
#define BIO_TYPE_TCL	(19|0x0400)

/*
 * Defines for State.flags
 */
#define TLS_TCL_ASYNC	(1<<0)	/* non-blocking mode */
#define TLS_TCL_SERVER	(1<<1)	/* Server-Side */
#define TLS_TCL_INIT	(1<<2)	/* Initializing connection */
#define TLS_TCL_DEBUG	(1<<3)	/* Show debug tracing */
#define TLS_TCL_CALLBACK	(1<<4)	/* In a callback, prevent update
					 * looping problem. [Bug 1652380] */
#define TLS_TCL_HANDSHAKE_FAILED (1<<5) /* Set on handshake failures and once
                                         * set, all further I/O will result
                                         * in ECONNABORTED errors. */

#define TLS_TCL_DELAY (5)

/*
 * This structure describes the per-instance state
 * of an ssl channel.
 *
 * The SSL processing context is maintained here, in the ClientData
 */
typedef struct State {
	Tcl_Channel self;       /* this socket channel */
	Tcl_TimerToken timer;

	int flags;              /* see State.flags above  */
	int watchMask;          /* current WatchProc mask */
	int mode;               /* current mode of parent channel */

	Tcl_Interp *interp;     /* interpreter in which this resides */
	Tcl_Obj *callback;      /* script called for tracing, verifying and errors */
	Tcl_Obj *password;      /* script called for certificate password */ 

	int vflags;             /* verify flags */
	SSL *ssl;               /* Struct for SSL processing */
	SSL_CTX *ctx;           /* SSL Context */
	BIO *bio;               /* Struct for SSL processing */
	BIO *p_bio;             /* Parent BIO (that is layered on Tcl_Channel) */

	char *err;
} State;

#ifdef USE_TCL_STUBS
#ifndef Tcl_StackChannel
#error "Unable to compile on this version of Tcl"
#endif /* Tcl_GetStackedChannel */
#endif /* USE_TCL_STUBS */

/*
 * Forward declarations
 */
Tcl_ChannelType *Tls_ChannelType(void);
Tcl_Channel     Tls_GetParent(State *statePtr);

Tcl_Obj         *Tls_NewX509Obj(Tcl_Interp *interp, X509 *cert);
void            Tls_Error(State *statePtr, char *msg);
void            Tls_Free(char *blockPtr);
void            Tls_Clean(State *statePtr);
int             Tls_WaitForConnect(State *statePtr, int *errorCodePtr);

BIO             *BIO_new_tcl(State* statePtr, int flags);

#endif /* _TLSINT_H */
