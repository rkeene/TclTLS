/*
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 *
 * $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tlsInt.h,v 1.5 2000/06/06 01:34:12 welch Exp $
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
#ifndef _TSLINT_H
#define _TLSINT_H

#include "tls.h"
#include <errno.h>

#ifdef NO_PATENTS
#define NO_IDEA
#define NO_RC2
#define NO_RC4
#define NO_RC5
#define NO_RSA
#define NO_SSL2
#endif

#ifdef BSAFE
#include <ssl.h>
#else
#include <openssl/ssl.h>
#endif

#ifdef TCL_STORAGE_CLASS
# undef TCL_STORAGE_CLASS
#endif
#ifdef BUILD_tls
# define TCL_STORAGE_CLASS DLLEXPORT
#else
# define TCL_STORAGE_CLASS DLLIMPORT
#endif
 
#ifndef ECONNABORTED
#define ECONNABORTED	130	/* Software caused connection abort */
#endif
#ifndef ECONNRESET
#define ECONNRESET	131	/* Connection reset by peer */
#endif

#ifdef DEBUG
#define dprintf fprintf
#else
#define dprintf if (0) fprintf
#endif

#define SSL_ERROR(ssl,err)	\
	    ((char*)ERR_reason_error_string(SSL_get_error((ssl),(err))))
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

#define TLS_TCL_DELAY (5)

/*
 * This structure describes the per-instance state
 * of an ssl channel.
 *
 * The SSL processing context is maintained here, in the ClientData
 */
typedef struct State {
    Tcl_Channel self;	/* this socket channel */
#if TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION < 2
    Tcl_Channel parent;	/* underlying channel */
#endif
    Tcl_TimerToken timer;

    int flags;		/* currently only CHANNEL_ASYNC */
    int watchMask;	/* current WatchProc mask */
    int mode;		/* current mode of parent channel */

    Tcl_Interp *interp;	/* interpreter in which this resides */
    Tcl_Obj *callback;	/* script called for tracing, verifying and errors */

    int vflags;		/* verify flags */
    SSL *ssl;		/* Struct for SSL processing */
    SSL_CTX *ctx;	/* SSL Context */
    BIO *bio;		/* Struct for SSL processing */
    BIO *p_bio;		/* Parent BIO (that is layered on Tcl_Channel) */

    char *err;
} State;

/*
 * Forward declarations
 */

EXTERN Tcl_ChannelType *Tls_ChannelType _ANSI_ARGS_((void));
EXTERN Tcl_Channel	Tls_GetParent _ANSI_ARGS_((State *statePtr));

EXTERN Tcl_Obj*		Tls_NewX509Obj _ANSI_ARGS_ (( Tcl_Interp *interp, X509 *cert));
EXTERN void		Tls_Error _ANSI_ARGS_ ((State *statePtr, char *msg));
EXTERN void		Tls_Free _ANSI_ARGS_ ((char *blockPtr));
EXTERN void		Tls_Clean _ANSI_ARGS_ ((State *statePtr));
EXTERN int		Tls_WaitForConnect _ANSI_ARGS_(( State *statePtr,
							int *errorCodePtr));

EXTERN BIO_METHOD *	BIO_s_tcl _ANSI_ARGS_((void));
EXTERN BIO *		BIO_new_tcl _ANSI_ARGS_((State* statePtr, int flags));

#endif /* _TLSINT_H */
