/*
 * Copyright (C) 1997-1999 Matt Newman <matt@novadigm.com>
 *
 * $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tls.c,v 1.6.2.1 2000/07/11 04:58:46 hobbs Exp $
 *
 * TLS (aka SSL) Channel - can be layered on any bi-directional
 * Tcl_Channel (Note: Requires Trf Core Patch)
 *
 * This was built (almost) from scratch based upon observation of
 * OpenSSL 0.9.2B
 *
 * Addition credit is due for Andreas Kupries (a.kupries@westend.com), for
 * providing the Tcl_ReplaceChannel mechanism and working closely with me
 * to enhance it to support full fileevent semantics.
 *
 * Also work done by the follow people provided the impetus to do this "right":
 *	tclSSL (Colin McCormack, Shared Technology)
 *	SSLtcl (Peter Antman)
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"

/*
 * External functions
 */

/*
 * Forward declarations
 */

#define F2N( key, dsp) \
	(((key) == NULL)?(char*)NULL:Tcl_TranslateFileName( interp, (key), (dsp)))
#define REASON()	ERR_reason_error_string(ERR_get_error())

static int	CiphersObjCmd _ANSI_ARGS_ ((ClientData clientData, Tcl_Interp *interp,
			   int objc, Tcl_Obj *CONST objv[]));

static int	HandshakeObjCmd _ANSI_ARGS_ ((ClientData clientData, Tcl_Interp *interp,
			   int objc, Tcl_Obj *CONST objv[]));

static int	ImportObjCmd _ANSI_ARGS_ ((ClientData clientData, Tcl_Interp *interp,
			   int objc, Tcl_Obj *CONST objv[]));

static int	StatusObjCmd _ANSI_ARGS_ ((ClientData clientData, Tcl_Interp *interp,
			   int objc, Tcl_Obj *CONST objv[]));
static SSL_CTX *CTX_Init _ANSI_ARGS_((Tcl_Interp *interp, int proto, char *key,
			    char *cert, char *CAdir, char *CAfile, char *ciphers));

#define TLS_PROTO_SSL2	0x01
#define TLS_PROTO_SSL3	0x02
#define TLS_PROTO_TLS1	0x04
#define ENABLED(flag, mask)	(((flag) & (mask)) == (mask))
/*
 * Static data structures
 */

#ifndef NO_DH
/* from openssl/apps/s_server.c */

static unsigned char dh512_p[]={
        0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
        0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
        0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
        0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
        0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
        0x47,0x74,0xE8,0x33,
        };
static unsigned char dh512_g[]={
	0x02,
};

static DH *get_dh512()
{
    DH *dh=NULL;

    if ((dh=DH_new()) == NULL) return(NULL);

    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);

    if ((dh->p == NULL) || (dh->g == NULL))
	return(NULL);
    return(dh);
}
#endif


/*
 * We lose the tcl password callback when we use the RSA BSAFE SSL-C 1.1.2
 * libraries instead of the current OpenSSL libraries.
 */

#ifdef BSAFE
#define PRE_OPENSSL_0_9_4 1
#endif

/*
 * Per OpenSSL 0.9.4 Compat
 */

#ifndef STACK_OF
#define STACK_OF(x)			STACK
#define sk_SSL_CIPHER_num(sk)		sk_num((sk))
#define sk_SSL_CIPHER_value( sk, index)	(SSL_CIPHER*)sk_value((sk), (index))
#endif


/*
 *-------------------------------------------------------------------
 *
 * InfoCallback --
 *
 *	monitors SSL connection process
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *-------------------------------------------------------------------
 */
static void
InfoCallback(SSL *ssl, int where, int ret)
{
    State *statePtr = (State*)SSL_get_app_data(ssl);
    Tcl_Obj *cmdPtr;
    char *major; char *minor;
    int w;

    if (statePtr->callback == (Tcl_Obj*)NULL)
	return;

    cmdPtr = Tcl_DuplicateObj(statePtr->callback);

#if 0
    if (where & SSL_CB_ALERT) {
	sev = SSL_alert_type_string_long(ret);
	if (strcmp( sev, "fatal")==0) {	/* Map to error */
	    Tls_Error(statePtr, SSL_ERROR(ssl, 0));
	    return;
	}
    }
#endif
    if (where & SSL_CB_HANDSHAKE_START) {
	major = "handshake";
	minor = "start";
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
	major = "handshake";
	minor = "done";
    } else {
	if (where & SSL_CB_ALERT)		major = "alert";
	else if (where & SSL_ST_CONNECT)	major = "connect";
	else if (where & SSL_ST_ACCEPT)		major = "accept";
	else					major = "unknown";

	if (where & SSL_CB_READ)		minor = "read";
	else if (where & SSL_CB_WRITE)		minor = "write";
	else if (where & SSL_CB_LOOP)		minor = "loop";
	else if (where & SSL_CB_EXIT)		minor = "exit";
	else					minor = "unknown";
    }


    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr, 
	    Tcl_NewStringObj( "info", -1));

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr, 
	    Tcl_NewStringObj( Tcl_GetChannelName(statePtr->self), -1) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( major, -1) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( minor, -1) );

    if (where & (SSL_CB_LOOP|SSL_CB_EXIT)) {
	Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( SSL_state_string_long(ssl), -1) );
    } else if (where & SSL_CB_ALERT) {
	char *cp = SSL_alert_desc_string_long(ret);

	Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( cp, -1) );
    } else {
	Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( SSL_state_string_long(ssl), -1) );
    }
    Tcl_Preserve( (ClientData) statePtr->interp);
    Tcl_Preserve( (ClientData) statePtr);

    Tcl_IncrRefCount( cmdPtr);
    (void) Tcl_GlobalEvalObj(statePtr->interp, cmdPtr);
    Tcl_DecrRefCount( cmdPtr);

    Tcl_Release( (ClientData) statePtr);
    Tcl_Release( (ClientData) statePtr->interp);

}

/*
 *-------------------------------------------------------------------
 *
 * VerifyCallback --
 *
 *	monitors SSL cerificate validation process
 *	This is called whenever a certificate is inspected
 *	 or decided invalid
 *
 * Results:
 *	ok - let SSL handle it
 *
 * Side effects:
 *	The err field of the currently operative State is set
 *	  to a string describing the SSL negotiation failure reason
 *-------------------------------------------------------------------
 */
static int
VerifyCallback(int ok, X509_STORE_CTX *ctx)
{
    SSL *ssl = (SSL*)X509_STORE_CTX_get_app_data(ctx);
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    State *statePtr = (State*)SSL_get_app_data(ssl);
    Tcl_Obj *cmdPtr;
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    char *errStr;

    dprintf(stderr, "Verify: %d\n", ok);

    if (!ok)
	errStr = (char*)X509_verify_cert_error_string(err);
    else
	errStr = (char *)0;

    if (statePtr->callback == (Tcl_Obj*)NULL) {
	if (statePtr->vflags & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
	    return ok;
	else
	    return 1;
    }
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr, 
	    Tcl_NewStringObj( "verify", -1));

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr, 
	    Tcl_NewStringObj( Tcl_GetChannelName(statePtr->self), -1) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewIntObj( depth) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tls_NewX509Obj( statePtr->interp, cert) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewIntObj( ok) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( errStr ? errStr : "", -1) );

    Tcl_Preserve( (ClientData) statePtr->interp);
    Tcl_Preserve( (ClientData) statePtr);

    Tcl_IncrRefCount( cmdPtr);
    if (Tcl_GlobalEvalObj(statePtr->interp, cmdPtr) != TCL_OK) {
	/* it got an error - reject the certificate */
	Tcl_BackgroundError( statePtr->interp);
	ok = 0;
    } else {
	if (Tcl_GetIntFromObj( statePtr->interp,
		    Tcl_GetObjResult( statePtr->interp), &ok) != TCL_OK) {
	    Tcl_BackgroundError( statePtr->interp);
	    ok = 0;
	}
    }
    Tcl_DecrRefCount( cmdPtr);

    Tcl_Release( (ClientData) statePtr);
    Tcl_Release( (ClientData) statePtr->interp);

    return(ok);	/* leave the disposition as SSL set it */
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Error --
 *
 *	Calls callback with $fd and $msg - so the callback can decide
 *	what to do with errors.
 *
 * Results:
 *	ok - let SSL handle it
 *
 * Side effects:
 *	The err field of the currently operative State is set
 *	  to a string describing the SSL negotiation failure reason
 *-------------------------------------------------------------------
 */
void
Tls_Error(State *statePtr, char *msg)
{
    Tcl_Obj *cmdPtr;

    if (msg && *msg) {
	Tcl_SetErrorCode( statePtr->interp, "SSL", msg, (char *)NULL);
    } else {
	msg = Tcl_GetStringFromObj(Tcl_GetObjResult(statePtr->interp), NULL);
    }
    statePtr->err = msg;

    if (statePtr->callback == (Tcl_Obj*)NULL) {
	char buf[BUFSIZ];
	sprintf(buf, "SSL channel \"%s\": error: %s",
	    Tcl_GetChannelName(statePtr->self), msg);
	Tcl_SetResult( statePtr->interp, buf, TCL_VOLATILE);
	Tcl_BackgroundError( statePtr->interp);
	return;
    }
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr, 
	    Tcl_NewStringObj( "error", -1));

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr, 
	    Tcl_NewStringObj( Tcl_GetChannelName(statePtr->self), -1) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( msg, -1) );

    Tcl_Preserve( (ClientData) statePtr->interp);
    Tcl_Preserve( (ClientData) statePtr);

    Tcl_IncrRefCount( cmdPtr);
    if (Tcl_GlobalEvalObj(statePtr->interp, cmdPtr) != TCL_OK) {
	Tcl_BackgroundError( statePtr->interp);
    }
    Tcl_DecrRefCount( cmdPtr);

    Tcl_Release( (ClientData) statePtr);
    Tcl_Release( (ClientData) statePtr->interp);
}

/*
 *-------------------------------------------------------------------
 *
 * PasswordCallback -- 
 *
 *	Called when a password is needed to unpack RSA and PEM keys
 *	Evals the tcl proc:  tls::password and returns the result as
 *	the password
 *-------------------------------------------------------------------
 */
#ifdef PRE_OPENSSL_0_9_4
/*
 * No way to handle user-data therefore no way without a global
 * variable to access the Tcl interpreter.
*/
static int
PasswordCallback(char *buf, int size, int verify)
{
    return -1;
}
#else
static int
PasswordCallback(char *buf, int size, int verify, void *udata)
{
    Tcl_Interp *interp = (Tcl_Interp*)udata;

    if (Tcl_Eval(interp, "tls::password") == TCL_OK) {
	char *ret = Tcl_GetStringResult(interp);
        strncpy(buf, ret, size);
	return strlen(ret);
    } else {
	return -1;
    }
}
#endif

/*
 *-------------------------------------------------------------------
 *
 * CiphersObjCmd -- list available ciphers
 *
 *	This procedure is invoked to process the "tls::ciphers" command
 *	to list available ciphers, based upon protocol selected.
 *
 * Results:
 *	A standard Tcl result list.
 *
 * Side effects:
 *	constructs and destroys SSL context (CTX)
 *
 *-------------------------------------------------------------------
 */
static int
CiphersObjCmd(clientData, interp, objc, objv)
    ClientData clientData;	/* Not used. */
    Tcl_Interp *interp;
    int objc;
    Tcl_Obj	*CONST objv[];
{
    static char *protocols[] = {
	"ssl2",
	"ssl3",
	"tls1",
	NULL
    };
    enum protocol {
	TLS_SSL2,
	TLS_SSL3,
	TLS_TLS1,
	TLS_NONE
    };
    Tcl_Obj *objPtr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *sk;
    char *cp, buf[BUFSIZ];
    int index, verbose = 0;

    if (objc < 2 || objc > 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "protocol ?verbose?");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj( interp, objv[1], protocols, "protocol", 0,
	&index) != TCL_OK) {
	return TCL_ERROR;
    }
    if (objc > 2 && Tcl_GetBooleanFromObj( interp, objv[2],
	&verbose) != TCL_OK) {
	return TCL_ERROR;
    }
    switch ((enum protocol)index) {
    case TLS_SSL2:
#if defined(NO_SSL2)
		Tcl_AppendResult(interp, "protocol not supported", NULL);
		return TCL_ERROR;
#else
		ctx = SSL_CTX_new(SSLv2_method()); break;
#endif
    case TLS_SSL3:
#if defined(NO_SSL3)
		Tcl_AppendResult(interp, "protocol not supported", NULL);
		return TCL_ERROR;
#else
		ctx = SSL_CTX_new(SSLv3_method()); break;
#endif
    case TLS_TLS1:
#if defined(NO_TLS1)
		Tcl_AppendResult(interp, "protocol not supported", NULL);
		return TCL_ERROR;
#else
		ctx = SSL_CTX_new(TLSv1_method()); break;
#endif
    }
    if (ctx == NULL) {
	Tcl_AppendResult(interp, REASON(),
	    (char *) NULL);
	return TCL_ERROR;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
	Tcl_AppendResult(interp, REASON(),
	    (char *) NULL);
	SSL_CTX_free(ctx);
	return TCL_ERROR;
    }
    objPtr = Tcl_NewListObj( 0, NULL);

    if (!verbose) {
	for (index = 0; ; index++) {
	    cp = (char*)SSL_get_cipher_list( ssl, index);
	    if (cp == NULL) break;
	    Tcl_ListObjAppendElement( interp, objPtr,
		Tcl_NewStringObj( cp, -1) );
	}
    } else {
	sk = SSL_get_ciphers(ssl);

	for (index = 0; index < sk_SSL_CIPHER_num(sk); index++) {
	    register int i;
	    SSL_CIPHER_description( sk_SSL_CIPHER_value( sk, index),
				    buf, sizeof(buf));
	    for (i = strlen(buf) - 1; i ; i--) {
		if (buf[i] == ' ' || buf[i] == '\n' ||
		    buf[i] == '\r' || buf[i] == '\t') {
		    buf[i] = '\0';
		} else {
		    break;
		}
	    }
	    Tcl_ListObjAppendElement( interp, objPtr,
		Tcl_NewStringObj( buf, -1) );
	}
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    Tcl_SetObjResult( interp, objPtr);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * HandshakeObjCmd --
 *
 *	This command is used to verify whether the handshake is complete
 *	or not.
 *
 * Results:
 *	A standard Tcl result. 1 means handshake complete, 0 means pending.
 *
 * Side effects:
 *	May force SSL negotiation to take place.
 *
 *-------------------------------------------------------------------
 */

static int
HandshakeObjCmd(clientData, interp, objc, objv)
    ClientData clientData;	/* Not used. */
    Tcl_Interp *interp;
    int objc;
    Tcl_Obj *CONST objv[];
{
    Tcl_Channel chan;		/* The channel to set a mode on. */
    State *statePtr;		/* client state for ssl socket */
    int ret = 1;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
        return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL);
    if (chan == (Tcl_Channel) NULL) {
        return TCL_ERROR;
    }
#ifdef TCL_CHANNEL_VERSION_2
    /*
     * Make sure to operate on the topmost channel
     */
    chan = Tcl_GetTopChannel(chan);
#endif
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
        Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
                "\": not a TLS channel", NULL);
        return TCL_ERROR;
    }
    statePtr = (State *)Tcl_GetChannelInstanceData( chan);

    if (!SSL_is_init_finished(statePtr->ssl)) {
	int err;
	ret = Tls_WaitForConnect(statePtr, &err);
	if (ret < 0) {
	    char *errStr = statePtr->err;
	    Tcl_ResetResult(interp);
	    Tcl_SetErrno(err);

	    if (!errStr || *errStr == 0)
	        errStr = Tcl_PosixError(interp);

	    Tcl_AppendResult(interp, "handshake failed: ", errStr, (char*)NULL);
	    return TCL_ERROR;
	}
    }
    Tcl_SetObjResult(interp, Tcl_NewIntObj(ret));
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * ImportObjCmd --
 *
 *	This procedure is invoked to process the "ssl" command
 *
 *	The ssl command pushes SSL over a (newly connected) tcp socket
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	May modify the behavior of an IO channel.
 *
 *-------------------------------------------------------------------
 */

static int
ImportObjCmd(clientData, interp, objc, objv)
    ClientData clientData;	/* Not used. */
    Tcl_Interp *interp;
    int objc;
    Tcl_Obj *CONST objv[];
{
    Tcl_Channel chan;		/* The channel to set a mode on. */
    BIO *bio;
    State *statePtr;		/* client state for ssl socket */
    SSL_CTX *ctx = NULL;
    Tcl_Obj *script = NULL;
    int idx;
    int flags = TLS_TCL_INIT;
    int server = 0;		/* is connection incoming or outgoing? */
    char *key = NULL;
    char *cert = NULL;
    char *ciphers = NULL;
    char *CAfile = NULL;
    char *CAdir = NULL;
    char *model = NULL;
#if defined(NO_SSL2)
    int ssl2 = 0;
#else
    int ssl2 = 1;
#endif
#if defined(NO_SSL3)
    int ssl3 = 0;
#else
    int ssl3 = 1;
#endif
#if defined(NO_SSL2) && defined(NO_SSL3)
    int tls1 = 1;
#else
    int tls1 = 0;
#endif
    int proto = 0;
    int verify = 0, require = 0, request = 1;

    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel ?options?");
        return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL);
    if (chan == (Tcl_Channel) NULL) {
        return TCL_ERROR;
    }
#ifdef TCL_CHANNEL_VERSION_2
    /*
     * Make sure to operate on the topmost channel
     */
    chan = Tcl_GetTopChannel(chan);
#endif

    for (idx = 2; idx < objc; idx++) {
	char *opt = Tcl_GetStringFromObj(objv[idx], NULL);

	if (opt[0] != '-')
	    break;

	OPTSTR( "-cafile", CAfile);
	OPTSTR( "-cadir", CAdir);
	OPTSTR( "-certfile", cert);
	OPTSTR( "-cipher", ciphers);
	OPTOBJ( "-command", script);
	OPTSTR( "-keyfile", key);
	OPTSTR( "-model", model);
	OPTBOOL( "-require", require);
	OPTBOOL( "-request", request);
	OPTBOOL( "-server", server);

	OPTBOOL( "-ssl2", ssl2);
	OPTBOOL( "-ssl3", ssl3);
	OPTBOOL( "-tls1", tls1);

	OPTBAD( "option", "-cafile, -cadir, -certfile, -cipher, -command, -keyfile, -model, -require, -request, -ssl2, -ssl3, -server, or -tls1");

	return TCL_ERROR;
    }
    if (request) verify |= SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_PEER;
    if (request && require) verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (verify == 0) verify = SSL_VERIFY_NONE;

    proto |= (ssl2 ? TLS_PROTO_SSL2 : 0);
    proto |= (ssl3 ? TLS_PROTO_SSL3 : 0);
    proto |= (tls1 ? TLS_PROTO_TLS1 : 0);

    /* reset to NULL if blank string provided */
    if (cert && !*cert) cert = NULL;
    if (key && !*key) key = NULL;
    if (ciphers && !*ciphers) ciphers = NULL;
    if (CAfile && !*CAfile) CAfile = NULL;
    if (CAdir && !*CAdir) CAdir = NULL;

    if (model != NULL) {
	int mode;
	/* Get the "model" context */
	chan = Tcl_GetChannel( interp, model, &mode);
	if (chan == (Tcl_Channel)0) {
	    return TCL_ERROR;
	}
#ifdef TCL_CHANNEL_VERSION_2
	/*
	 * Make sure to operate on the topmost channel
	 */
	chan = Tcl_GetTopChannel(chan);
#endif
	if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	    Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		    "\": not a TLS channel", NULL);
	    return TCL_ERROR;
	}
	statePtr = (State *)Tcl_GetChannelInstanceData( chan);
	ctx = statePtr->ctx;
    } else {
	if ((ctx = CTX_Init( interp, proto, key, cert, CAdir, CAfile, ciphers))
	    == (SSL_CTX*)0) {
	    return TCL_ERROR;
	}
    }

    /* new SSL state */
    statePtr = (State *) Tcl_Alloc((unsigned) sizeof(State));
    statePtr->self = (Tcl_Channel)NULL;
    statePtr->timer = (Tcl_TimerToken)NULL;

    statePtr->flags = flags;
    statePtr->watchMask = 0;
    statePtr->mode = 0;

    statePtr->interp = interp;
    statePtr->callback = (Tcl_Obj *)0;

    statePtr->vflags = verify;
    statePtr->ssl = (SSL*)0;
    statePtr->ctx = ctx;
    statePtr->bio = (BIO*)0;
    statePtr->p_bio = (BIO*)0;

    statePtr->err = "";

    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    Tcl_SetChannelOption(interp, chan, "-buffering", "none");

#if TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION < 2
    statePtr->parent = chan;
    statePtr->self = Tcl_ReplaceChannel( interp,
				Tls_ChannelType(), (ClientData) statePtr,
			       (TCL_READABLE | TCL_WRITABLE), statePtr->parent);
#else
#ifdef TCL_CHANNEL_VERSION_2
    statePtr->self = Tcl_StackChannel(interp, Tls_ChannelType(),
	    (ClientData) statePtr, (TCL_READABLE | TCL_WRITABLE), chan);
#else
    statePtr->self = chan;
    Tcl_StackChannel( interp, Tls_ChannelType(), (ClientData) statePtr,
	    (TCL_READABLE | TCL_WRITABLE), chan);
#endif
#endif
    if (statePtr->self == (Tcl_Channel) NULL) {
	/*
	 * No use of Tcl_EventuallyFree because no possible Tcl_Preserve.
	 */
	Tls_Free((char *) statePtr);
        return TCL_ERROR;
    }

    /* allocate script */
    if (script) {
	char * tmp = Tcl_GetStringFromObj(script, NULL);
	if (tmp && *tmp) {
	    statePtr->callback = Tcl_DuplicateObj(script);
	    Tcl_IncrRefCount( statePtr->callback);
	}
    }
    /* This is only needed because of a bug in OpenSSL, where the
     * ssl->verify_callback is not referenced!!! (Must be done
     * *before* SSL_new() is called!
     */
    SSL_CTX_set_verify(statePtr->ctx, verify, VerifyCallback);

    /*
     * SSL Initialization
     */

    statePtr->ssl = SSL_new(statePtr->ctx);
    if (!statePtr->ssl) {
        /* SSL library error */
        Tcl_AppendResult(interp,
                         "couldn't construct ssl session: ", REASON(),
                         (char *) NULL);
	Tls_Free((char *) statePtr);
        return TCL_ERROR;
    }

    /*
     * SSL Callbacks
     */

    SSL_set_app_data(statePtr->ssl, (VOID *)statePtr);	/* point back to us */

    /*
     * The following is broken - we need is to set the
     * verify_mode, but the library ignores the verify_callback!!!
     */
    /*SSL_set_verify(statePtr->ssl, verify, VerifyCallback);*/

    SSL_CTX_set_info_callback( statePtr->ctx, InfoCallback);

    /* Create Tcl_Channel BIO Handler */
    statePtr->p_bio = bio = BIO_new_tcl( statePtr, BIO_CLOSE);
    statePtr->bio = BIO_new(BIO_f_ssl());

    if (server) {
	statePtr->flags |= TLS_TCL_SERVER;
	SSL_set_accept_state(statePtr->ssl);
    } else {
	SSL_set_connect_state(statePtr->ssl);
    }
    SSL_set_bio(statePtr->ssl, bio, bio);
    BIO_set_ssl(statePtr->bio, statePtr->ssl, BIO_CLOSE);

    /*
     * End of SSL Init
     */
    Tcl_SetResult(interp, Tcl_GetChannelName(statePtr->self), TCL_VOLATILE);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * CTX_Init -- construct a SSL_CTX instance
 *
 * Results:
 *	A valid SSL_CTX instance or NULL.
 *
 * Side effects:
 *	constructs SSL context (CTX)
 *
 *-------------------------------------------------------------------
 */

static SSL_CTX *
CTX_Init(interp, proto, key, cert, CAdir, CAfile, ciphers)
    Tcl_Interp *interp;
    int proto;
    char *key;
    char *cert;
    char *CAdir;
    char *CAfile;
    char *ciphers;
{
    SSL_CTX *ctx = NULL;
    Tcl_DString ds;
    Tcl_DString ds1;
    int off = 0;

    /* create SSL context */
#if !defined(NO_SSL2) && !defined(NO_SSL3)
    if (ENABLED(proto, TLS_PROTO_SSL2) &&
	ENABLED(proto, TLS_PROTO_SSL3)) {
	ctx = SSL_CTX_new(SSLv23_method());
    } else
#endif
    if (ENABLED(proto, TLS_PROTO_SSL2)) {
#if defined(NO_SSL2)
	Tcl_AppendResult(interp, "protocol not supported", NULL);
	return (SSL_CTX *)0;
#else
	ctx = SSL_CTX_new(SSLv2_method());
#endif
    } else if (ENABLED(proto, TLS_PROTO_TLS1)) {
	ctx = SSL_CTX_new(TLSv1_method());
    } else if (ENABLED(proto, TLS_PROTO_SSL3)) {
#if defined(NO_SSL3)
	Tcl_AppendResult(interp, "protocol not supported", NULL);
	return (SSL_CTX *)0;
#else
	ctx = SSL_CTX_new(SSLv3_method());
#endif
    } else {
	Tcl_AppendResult(interp, "no valid protocol selected", NULL);
	return (SSL_CTX *)0;
    }
    off |= (ENABLED(proto, TLS_PROTO_TLS1) ? 0 : SSL_OP_NO_TLSv1);
    off |= (ENABLED(proto, TLS_PROTO_SSL2) ? 0 : SSL_OP_NO_SSLv2);
    off |= (ENABLED(proto, TLS_PROTO_SSL3) ? 0 : SSL_OP_NO_SSLv3);

    SSL_CTX_set_app_data( ctx, (VOID*)interp);	/* remember the interpreter */
    SSL_CTX_set_options( ctx, SSL_OP_ALL);	/* all SSL bug workarounds */
    SSL_CTX_set_options( ctx, off);	/* all SSL bug workarounds */
    SSL_CTX_sess_set_cache_size( ctx, 128);

    if (ciphers != NULL)
	SSL_CTX_set_cipher_list(ctx, ciphers);

    /* set some callbacks */
    SSL_CTX_set_default_passwd_cb(ctx, PasswordCallback);

#ifndef BSAFE
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)interp);
#endif

#ifndef NO_DH
    {
	DH* dh = get_dh512();
	SSL_CTX_set_tmp_dh(ctx, dh);
	DH_free(dh);
    }
#endif

    /* set our certificate */
    if (cert != NULL) {
	Tcl_DStringInit(&ds);

        if (SSL_CTX_use_certificate_file(ctx, F2N( cert, &ds),
					SSL_FILETYPE_PEM) <= 0) {
	    Tcl_DStringFree(&ds);
            Tcl_AppendResult(interp,
                             "unable to set certificate file ", cert, ": ",
                             REASON(), (char *) NULL);
            SSL_CTX_free(ctx);
            return (SSL_CTX *)0;
        }

        /* get the private key associated with this certificate */
        if (key == NULL) key=cert;

        if (SSL_CTX_use_PrivateKey_file(ctx, F2N( key, &ds),
					SSL_FILETYPE_PEM) <= 0) {
	    Tcl_DStringFree(&ds);
            Tcl_AppendResult(interp,
                             "unable to set public key file ", key, " ",
                             REASON(), (char *) NULL);
            SSL_CTX_free(ctx);
            return (SSL_CTX *)0;
        }
	Tcl_DStringFree(&ds);
        /* Now we know that a key and cert have been set against
         * the SSL context */
        if (!SSL_CTX_check_private_key(ctx)) {
            Tcl_AppendResult(interp,
                             "private key does not match the certificate public key",
                             (char *) NULL);
            SSL_CTX_free(ctx);
            return (SSL_CTX *)0;
        }
    } else {
        cert = (char*)X509_get_default_cert_file();

        if (SSL_CTX_use_certificate_file(ctx, cert,
					SSL_FILETYPE_PEM) <= 0) {
#if 0
	    Tcl_DStringFree(&ds);
            Tcl_AppendResult(interp,
                             "unable to use default certificate file ", cert, ": ",
                             REASON(), (char *) NULL);
            SSL_CTX_free(ctx);
            return (SSL_CTX *)0;
#endif
        }
    }
	
    Tcl_DStringInit(&ds);
    Tcl_DStringInit(&ds1);
    if (!SSL_CTX_load_verify_locations(ctx, F2N(CAfile, &ds), F2N(CAdir, &ds1)) ||
        !SSL_CTX_set_default_verify_paths(ctx)) {
#if 0
	Tcl_DStringFree(&ds);
	Tcl_DStringFree(&ds1);
	/* Don't currently care if this fails */
	Tcl_AppendResult(interp, "SSL default verify paths: ",
                             REASON(), (char *) NULL);
	SSL_CTX_free(ctx);
	return (SSL_CTX *)0;
#endif
    }
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file( F2N(CAfile, &ds) ));

    Tcl_DStringFree(&ds);
    Tcl_DStringFree(&ds1);
    return ctx;
}

/*
 *-------------------------------------------------------------------
 *
 * StatusObjCmd -- return certificate for connected peer.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
StatusObjCmd(clientData, interp, objc, objv)
    ClientData clientData;	/* Not used. */
    Tcl_Interp *interp;
    int objc;
    Tcl_Obj	*CONST objv[];
{
    State *statePtr;
    X509 *peer;
    Tcl_Obj *objPtr;
    Tcl_Channel chan;
    char *channelName, *ciphers;
    int mode;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "channel");
        return TCL_ERROR;
    }
    channelName = Tcl_GetStringFromObj(objv[1], NULL);

    chan = Tcl_GetChannel( interp, channelName, &mode);
    if (chan == (Tcl_Channel)0) {
	return TCL_ERROR;
    }
#ifdef TCL_CHANNEL_VERSION_2
    /*
     * Make sure to operate on the topmost channel
     */
    chan = Tcl_GetTopChannel(chan);
#endif
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
        Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
                "\": not a TLS channel", NULL);
        return TCL_ERROR;
    }
    statePtr = (State *)Tcl_GetChannelInstanceData( chan);
    peer = SSL_get_peer_certificate(statePtr->ssl);
    if (peer)
	objPtr = Tls_NewX509Obj( interp, peer);
    else
	objPtr = Tcl_NewListObj( 0, NULL);

    ciphers = (char*)SSL_get_cipher(statePtr->ssl);
    if (ciphers != NULL && strcmp(ciphers, "(NONE)")!=0) {
	Tcl_ListObjAppendElement( interp, objPtr,
		Tcl_NewStringObj( "cipher", -1) );
	Tcl_ListObjAppendElement( interp, objPtr,
		Tcl_NewStringObj( SSL_get_cipher(statePtr->ssl), -1) );
    }
    Tcl_SetObjResult( interp, objPtr);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Free --
 *
 *	This procedure cleans up when a SSL socket based channel
 *	is closed and its reference count falls below 1
 *
 * Results:
 *	none
 *
 * Side effects:
 *	Frees all the state
 *
 *-------------------------------------------------------------------
 */
void
Tls_Free( char *blockPtr )
{
    State *statePtr = (State *)blockPtr;

    Tls_Clean(statePtr);
    Tcl_Free(blockPtr);
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Clean --
 *
 *	This procedure cleans up when a SSL socket based channel
 *	is closed and its reference count falls below 1.  This should
 *	be called synchronously by the CloseProc, not in the
 *	EventuallyFree callback.
 *
 * Results:
 *	none
 *
 * Side effects:
 *	Frees all the state
 *
 *-------------------------------------------------------------------
 */
void
Tls_Clean(State *statePtr)
{
    /* we're assuming here that we're single-threaded */
    if (statePtr->ssl) {
	SSL_shutdown(statePtr->ssl);
	SSL_free(statePtr->ssl);
	statePtr->ssl = NULL;
    }
    if (statePtr->callback) {
	Tcl_DecrRefCount(statePtr->callback);
	statePtr->callback = NULL;
    }

    if (statePtr->timer != (Tcl_TimerToken)NULL) {
	Tcl_DeleteTimerHandler (statePtr->timer);
	statePtr->timer = NULL;
    }
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Init --
 *
 *	This is a package initialization procedure, which is called
 *	by Tcl when this package is to be added to an interpreter.
 *
 * Results:  Ssl configured and loaded
 *
 * Side effects:
 *	 create the ssl command, initialise ssl context
 *
 *-------------------------------------------------------------------
 */

int
Tls_Init(Tcl_Interp *interp)		/* Interpreter in which the package is
                                         * to be made available. */
{
#if TCL_MAJOR_VERSION >= 8 && TCL_MINOR_VERSION >= 2
    if (!Tcl_InitStubs(interp, TCL_VERSION, 0)) {
        return TCL_ERROR;
    }
#endif
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    SSL_library_init();

    Tcl_CreateObjCommand(interp, "tls::ciphers", CiphersObjCmd , (ClientData) 0,
                      (Tcl_CmdDeleteProc *) NULL);

    Tcl_CreateObjCommand(interp, "tls::handshake", HandshakeObjCmd , (ClientData) 0,
                      (Tcl_CmdDeleteProc *) NULL);

    Tcl_CreateObjCommand(interp, "tls::import", ImportObjCmd , (ClientData) 0,
                      (Tcl_CmdDeleteProc *) NULL);

    Tcl_CreateObjCommand(interp, "tls::status", StatusObjCmd , (ClientData) 0,
                      (Tcl_CmdDeleteProc *) NULL);

    return Tcl_PkgProvide(interp, PACKAGE, VERSION);
}


/*
 *------------------------------------------------------*
 *
 *	Tls_SafeInit --
 *
 *	------------------------------------------------*
 *	Standard procedure required by 'load'. 
 *	Initializes this extension for a safe interpreter.
 *	------------------------------------------------*
 *
 *	Sideeffects:
 *		As of 'Tls_Init'
 *
 *	Result:
 *		A standard Tcl error code.
 *
 *------------------------------------------------------*
 */

int
Tls_SafeInit (Tcl_Interp* interp)
{
    return Tls_Init (interp);
}
