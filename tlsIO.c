/*
 * Copyright (C) 1997-1999 Matt Newman <matt@novadigm.com>
 *
 * $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tlsIO.c,v 1.1.1.1 2000/01/19 22:10:58 aborr Exp $
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
 * Also work done by the follow people provided the impetus to do this "right":
 *	tclSSL (Colin McCormack, Shared Technology)
 *	SSLtcl (Peter Antman)
 *
 */

#include "tlsInt.h"

/*
 * External functions
 */

/*
 * Local Defines
 */

/*
 * Forward declarations
 */

static int	BlockModeProc _ANSI_ARGS_((ClientData instanceData, int mode));
static int	CloseProc _ANSI_ARGS_ ((ClientData instanceData, Tcl_Interp *interp));
static int	InputProc _ANSI_ARGS_((ClientData instanceData,
			    char *buf, int bufSize, int *errorCodePtr));
static int	OutputProc _ANSI_ARGS_((ClientData instanceData,
			    char *buf, int toWrite, int *errorCodePtr));
static int	GetOptionProc _ANSI_ARGS_ ((ClientData instanceData,
			    Tcl_Interp *interp, char *optionName, Tcl_DString *dsPtr));
static void	WatchProc _ANSI_ARGS_((ClientData instanceData, int mask));
static int	GetHandleProc _ANSI_ARGS_ ((ClientData instanceData,
			    int direction, ClientData *handlePtr));
static void	ChannelHandler _ANSI_ARGS_ ((ClientData clientData, int mask));
static void	ChannelHandlerTimer _ANSI_ARGS_ ((ClientData clientData));

/*
 * This structure describes the channel type structure for TCP socket
 * based IO:
 */

static Tcl_ChannelType tlsChannelType = {
    "tls",		/* Type name. */
    BlockModeProc,	/* Set blocking/nonblocking mode.*/
    CloseProc,		/* Close proc. */
    InputProc,		/* Input proc. */
    OutputProc,		/* Output proc. */
    NULL,		/* Seek proc. */
    NULL,		/* Set option proc. */
    GetOptionProc,	/* Get option proc. */
    WatchProc,		/* Initialize notifier. */
    GetHandleProc,	/* Get file handle out of channel. */
};

Tcl_ChannelType *Tls_ChannelType()
{
    return &tlsChannelType;
}

/*
 *-------------------------------------------------------------------
 *
 * BlockModeProc --
 *
 *	This procedure is invoked by the generic IO level
 *       to set blocking and nonblocking modes
 * Results:
 *	0 if successful, errno when failed.
 *
 * Side effects:
 *	Sets the device into blocking or nonblocking mode.
 *
 *-------------------------------------------------------------------
 */

static int
BlockModeProc(ClientData instanceData,	/* Socket state. */
                 int mode)			/* The mode to set. Can be one of
						* TCL_MODE_BLOCKING or
						* TCL_MODE_NONBLOCKING. */
{
    State *statePtr = (State *) instanceData;

    if (mode == TCL_MODE_NONBLOCKING) {
	statePtr->flags |= TLS_TCL_ASYNC;
    } else {
	statePtr->flags &= ~(TLS_TCL_ASYNC);
    }
    return Tcl_SetChannelOption(statePtr->interp, Tls_GetParent(statePtr),
		"-blocking", (mode == TCL_MODE_NONBLOCKING) ? "0" : "1");
}

/*
 *-------------------------------------------------------------------
 *
 * CloseProc --
 *
 *	This procedure is invoked by the generic IO level to perform
 *	channel-type-specific cleanup when a SSL socket based channel
 *	is closed.
 *
 *	Note: we leave the underlying socket alone, is this right?
 *
 * Results:
 *	0 if successful, the value of Tcl_GetErrno() if failed.
 *
 * Side effects:
 *	Closes the socket of the channel.
 *
 *-------------------------------------------------------------------
 */
static int
CloseProc(ClientData instanceData,	/* The socket to close. */
             Tcl_Interp *interp)	/* For error reporting - unused. */
{
    State *statePtr = (State *) instanceData;
#if TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION < 2
    Tcl_Channel parent = Tls_GetParent(statePtr);
#else
    Tcl_Channel parent = statePtr->self; /* 'self' already refers to our parent */
#endif

    dprintf(stderr,"\nCloseProc(0x%x)", statePtr);
    /*
     * Remove event handler to underlying channel, this could
     * be because we are closing for real, or being "unstacked".
     */

    Tcl_DeleteChannelHandler( parent,
	ChannelHandler, (ClientData) statePtr);

    if (statePtr->timer != (Tcl_TimerToken)NULL) {
	Tcl_DeleteTimerHandler (statePtr->timer);
	statePtr->timer = (Tcl_TimerToken)NULL;
    }

    Tcl_EventuallyFree( (ClientData)statePtr, Tls_Free);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * InputProc --
 *
 *	This procedure is invoked by the generic IO level
 *       to read input from a SSL socket based channel.
 *
 * Results:
 *	The number of bytes read is returned or -1 on error. An output
 *	argument contains the POSIX error code on error, or zero if no
 *	error occurred.
 *
 * Side effects:
 *	Reads input from the input device of the channel.
 *
 *-------------------------------------------------------------------
 */

static int
InputProc(ClientData instanceData,	/* Socket state. */
             char *buf,			/* Where to store data read. */
             int bufSize,		/* How much space is available
                                         * in the buffer? */
             int *errorCodePtr)		/* Where to store error code. */
{
    State *statePtr = (State *) instanceData;
    int bytesRead;			/* How many bytes were read? */

    *errorCodePtr = 0;

    dprintf(stderr,"\nBIO_read(%d)", bufSize);

    if (!SSL_is_init_finished(statePtr->ssl)) {
	bytesRead = Tls_WaitForConnect(statePtr, errorCodePtr);
	if (bytesRead <= 0) {
	    goto input;
	}
    }
    if (statePtr->flags & TLS_TCL_INIT) {
	statePtr->flags &= ~(TLS_TCL_INIT);
    }
    bytesRead = BIO_read(statePtr->bio, buf, bufSize);
    dprintf(stderr,"\nBIO_read -> %d", bytesRead);

    if (bytesRead < 0) {
	int err = SSL_get_error(statePtr->ssl, bytesRead);

	if (err == SSL_ERROR_SSL) {
	    Tls_Error(statePtr, SSL_ERROR(statePtr->ssl, bytesRead));
	    *errorCodePtr = ECONNABORTED;
	    goto input;
	} else if (BIO_should_retry(statePtr->bio)) {
	    dprintf(stderr,"RE! ");
	    *errorCodePtr = EAGAIN;
	    goto input;
	}
	if (Tcl_GetErrno() == ECONNRESET) {
	    /* Soft EOF */
	    bytesRead = 0;
	    goto input;
	} else {
	    *errorCodePtr = Tcl_GetErrno();
	    goto input;
	}
    }
input:
    dprintf(stderr, "\nInput(%d) -> %d [%d]", bufSize, bytesRead, *errorCodePtr);
    return bytesRead;
}

/*
 *-------------------------------------------------------------------
 *
 * OutputProc --
 *
 *	This procedure is invoked by the generic IO level
 *       to write output to a SSL socket based channel.
 *
 * Results:
 *	The number of bytes written is returned. An output argument is
 *	set to a POSIX error code if an error occurred, or zero.
 *
 * Side effects:
 *	Writes output on the output device of the channel.
 *
 *-------------------------------------------------------------------
 */

static int
OutputProc(ClientData instanceData,	/* Socket state. */
              char *buf,			/* The data buffer. */
              int toWrite,		/* How many bytes to write? */
              int *errorCodePtr)	/* Where to store error code. */
{
    State *statePtr = (State *) instanceData;
    int written, err;

    *errorCodePtr = 0;

    dprintf(stderr,"\nBIO_write(%d)", toWrite);

    if (!SSL_is_init_finished(statePtr->ssl)) {
	written = Tls_WaitForConnect(statePtr, errorCodePtr);
	if (written <= 0) {
	    goto output;
	}
    }
    if (statePtr->flags & TLS_TCL_INIT) {
	statePtr->flags &= ~(TLS_TCL_INIT);
    }
    if (toWrite == 0) {
	dprintf(stderr, "zero-write\n");
	BIO_flush(statePtr->bio);
	written = 0;
	goto output;
    } else {
	written = BIO_write(statePtr->bio, buf, toWrite);
	dprintf(stderr,"\nBIO_write(%d) -> [%d]", toWrite, written);
    }
    if (written < 0 || written == 0) {
	switch ((err = SSL_get_error(statePtr->ssl, written))) {
	case SSL_ERROR_NONE:
	    if (written <= 0) {
		written = 0;
		goto output;
	    }
	    break;
	case SSL_ERROR_WANT_WRITE:
	    dprintf(stderr,"write W BLOCK\n");
	    break;
	case SSL_ERROR_WANT_READ:
	    dprintf(stderr,"write R BLOCK\n");
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    dprintf(stderr,"write X BLOCK\n");
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    dprintf(stderr,"closed\n");
	    written = 0;
	    goto output;
	case SSL_ERROR_SYSCALL:
	    *errorCodePtr = Tcl_GetErrno();
	    dprintf(stderr,"[%d] syscall errr: %d\n", written, Tcl_GetErrno());
	    written = -1;
	    goto output;
	case SSL_ERROR_SSL:
	    Tls_Error(statePtr, SSL_ERROR(statePtr->ssl, written));
	    *errorCodePtr = ECONNABORTED;
	    written = -1;
	    goto output;
	default:
	    dprintf(stderr,"unknown err: %d\n", err);
	}
    }
output:
    dprintf(stderr, "\nOutput(%d) -> %d", toWrite, written);
    return written;
}

/*
 *-------------------------------------------------------------------
 *
 * GetOptionProc --
 *
 *	Computes an option value for a SSL socket based channel, or a
 *	list of all options and their values.
 *
 *	Note: This code is based on code contributed by John Haxby.
 *
 * Results:
 *	A standard Tcl result. The value of the specified option or a
 *	list of all options and	their values is returned in the
 *	supplied DString.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
GetOptionProc(ClientData instanceData,	/* Socket state. */
                 Tcl_Interp *interp,		/* For errors - can be NULL. */
                 char *optionName,		/* Name of the option to
                                                 * retrieve the value for, or
                                                 * NULL to get all options and
                                                 * their values. */
                 Tcl_DString *dsPtr)	         /* Where to store the computed value
                                                  * initialized by caller. */
{
    State *statePtr = (State *) instanceData;
    size_t len = 0;

    if (optionName != (char *) NULL) {
        len = strlen(optionName);
    }
#if 0
    if ((len == 0) ||
        ((len > 1) && (optionName[1] == 'c') &&
         (strncmp(optionName, "-cipher", len) == 0))) {
        if (len == 0) {
            Tcl_DStringAppendElement(dsPtr, "-cipher");
        }
        Tcl_DStringAppendElement(dsPtr, SSL_get_cipher(statePtr->ssl));
        if (len) {
            return TCL_OK;
        }
    }
#endif
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * WatchProc --
 *
 *	Initialize the notifier to watch Tcl_Files from this channel.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Sets up the notifier so that a future event on the channel
 *	will be seen by Tcl.
 *
 *-------------------------------------------------------------------
 */

static void
WatchProc(ClientData instanceData,	/* The socket state. */
             int mask)			/* Events of interest; an OR-ed
                                         * combination of TCL_READABLE,
                                         * TCL_WRITABLE and TCL_EXCEPTION. */
{
    State *statePtr = (State *) instanceData;

    if (mask == statePtr->watchMask)
	return;

    if (statePtr->watchMask) {
	/*
	 * Remove event handler to underlying channel, this could
	 * be because we are closing for real, or being "unstacked".
	 */
	Tcl_DeleteChannelHandler( Tls_GetParent(statePtr), ChannelHandler, (ClientData) statePtr);
    }
    statePtr->watchMask = mask;
    if (statePtr->watchMask) {
	/* Setup active monitor for events on underlying Channel */
	Tcl_CreateChannelHandler( Tls_GetParent(statePtr), statePtr->watchMask,
				ChannelHandler, (ClientData) statePtr);
    }
}

/*
 *-------------------------------------------------------------------
 *
 * GetHandleProc --
 *
 *	Called from Tcl_GetChannelFile to retrieve o/s file handler
 *	from the SSL socket based channel.
 *
 * Results:
 *	The appropriate Tcl_File or NULL if not present. 
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
GetHandleProc(ClientData instanceData,	/* The socket state. */
                 int direction,		/* Which Tcl_File to retrieve? */
                 ClientData *handlePtr)	/* Where to store the handle.  */
{
    State *statePtr = (State *) instanceData;

    return Tcl_GetChannelHandle (Tls_GetParent(statePtr), direction, handlePtr);
}

/*
 *------------------------------------------------------*
 *
 *      ChannelHandler --
 *
 *      ------------------------------------------------*
 *      Handler called by Tcl as a result of
 *      Tcl_CreateChannelHandler - to inform us of activity
 *      on the underlying channel.
 *      ------------------------------------------------*
 *
 *      Sideeffects:
 *              May generate subsequent calls to
 *              Tcl_NotifyChannel.
 *
 *      Result:
 *              None.
 *
 *------------------------------------------------------*
 */

static void
ChannelHandler (clientData, mask)
ClientData     clientData;
int            mask;
{
    State *statePtr = (State *) clientData;

dprintf(stderr, "HANDLER(0x%x)\n", mask);
    Tcl_Preserve( (ClientData)statePtr);

    if (mask & TCL_READABLE) {
	BIO_set_flags(statePtr->p_bio, BIO_FLAGS_READ);
    } else {
	BIO_clear_flags(statePtr->p_bio, BIO_FLAGS_READ);
    }

    if (mask & TCL_WRITABLE) {
	BIO_set_flags(statePtr->p_bio, BIO_FLAGS_WRITE);
    } else {
	BIO_clear_flags(statePtr->p_bio, BIO_FLAGS_WRITE);
    }

    mask = 0;
    if (BIO_wpending(statePtr->bio)) {
	mask |= TCL_WRITABLE;
    }
    if (BIO_pending(statePtr->bio)) {
	mask |= TCL_READABLE;
    }
    Tcl_NotifyChannel(statePtr->self, mask);

    if (statePtr->timer != (Tcl_TimerToken)NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken)NULL;
    }
    if ((mask & TCL_READABLE) && Tcl_InputBuffered (statePtr->self) > 0) {
	/*
	 * Data is waiting, flush it out in short time
	 */
	statePtr->timer = Tcl_CreateTimerHandler (TLS_TCL_DELAY, ChannelHandlerTimer,
					   (ClientData) statePtr);
    }
    Tcl_Release( (ClientData)statePtr);
}

/*
 *------------------------------------------------------*
 *
 *	ChannelHandlerTimer --
 *
 *	------------------------------------------------*
 *	Called by the notifier (-> timer) to flush out
 *	information waiting in channel buffers.
 *	------------------------------------------------*
 *
 *	Sideeffects:
 *		As of 'ChannelHandler'.
 *
 *	Result:
 *		None.
 *
 *------------------------------------------------------*
 */

static void
ChannelHandlerTimer (clientData)
ClientData clientData; /* Transformation to query */
{
    State *statePtr = (State *) clientData;
    int mask = 0;

    statePtr->timer = (Tcl_TimerToken) NULL;

    if (BIO_wpending(statePtr->bio)) {
	mask |= TCL_WRITABLE;
    }
    if (BIO_pending(statePtr->bio)) {
	mask |= TCL_READABLE;
    }
    Tcl_NotifyChannel(statePtr->self, mask);
}

/*
 *------------------------------------------------------*
 *
 *	Tls_WaitForConnect --
 *
 *	Sideeffects:
 *		Issues SSL_accept or SSL_connect
 *
 *	Result:
 *		None.
 *
 *------------------------------------------------------*
 */
int
Tls_WaitForConnect( statePtr, errorCodePtr)
    State *statePtr;
    int *errorCodePtr;		/* Where to store error code. */
{
    int err;

    dprintf(stderr,"\nWaitForConnect(0x%x)", statePtr);

    for (;;) {
	/* Not initialized yet! */
	if (statePtr->flags & TLS_TCL_SERVER) {
	    err = SSL_accept(statePtr->ssl);
	} else {
	    err = SSL_connect(statePtr->ssl);
	}
	/*SSL_write(statePtr->ssl, (char*)&err, 0);	HACK!!! */
	if (err > 0)
	    BIO_flush(statePtr->bio);

	if (err <= 0) {
	    int rc = SSL_get_error(statePtr->ssl, err);

	    if (rc == SSL_ERROR_SSL) {
		Tls_Error(statePtr, (char*)ERR_reason_error_string(ERR_get_error()));
		*errorCodePtr = ECONNABORTED;
		return -1;
	    } else if (BIO_should_retry(statePtr->bio)) {
		if (statePtr->flags & TLS_TCL_ASYNC) {
		    dprintf(stderr,"E! ");
		    *errorCodePtr = EAGAIN;
		    return -1;
		} else {
		    continue;
		}
	    } else if (err == 0) {
		dprintf(stderr,"CR! ");
		*errorCodePtr = ECONNRESET;
		return -1;
	    }
	    if (statePtr->flags & TLS_TCL_SERVER) {
		err = SSL_get_verify_result(statePtr->ssl);
		if (err != X509_V_OK) {
		    Tls_Error(statePtr, (char*)X509_verify_cert_error_string(err));
		    *errorCodePtr = ECONNABORTED;
		    return -1;
		}
	    }
	    *errorCodePtr = Tcl_GetErrno();
	    dprintf(stderr,"ERR(%d, %d) ", rc, *errorCodePtr);
	    return -1;
	}
	dprintf(stderr,"R0! ");
	return 1;
    }
}

Tcl_Channel
Tls_GetParent( statePtr )
    State *statePtr;
{
#if TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION < 2
    return statePtr->parent;
#else
    /* The reason for the existence of this procedure is
     * the fact that stacking a transform over another
     * transform will leave our internal pointer unchanged,
     * and thus pointing to the new transform, and not the
     * Channel structure containing the saved state of this
     * transform. This is the price to pay for leaving
     * Tcl_Channel references intact. The only other solution
     * is an extension of Tcl_ChannelType with another driver
     * procedure to notify a Channel about the (un)stacking.
     *
     * It walks the chain of Channel structures until it
     * finds the one pointing having 'ctrl' as instanceData
     * and then returns the superceding channel to that. (AK)
     */
 
  Tcl_Channel self = statePtr->self;
  Tcl_Channel next;

  while ((ClientData) statePtr != Tcl_GetChannelInstanceData (self)) {
    next = Tcl_GetStackedChannel (self);
    if (next == (Tcl_Channel) NULL) {
      /* 09/24/1999 Unstacking bug, found by Matt Newman <matt@sensus.org>.
       *
       * We were unable to find the channel structure for this
       * transformation in the chain of stacked channel. This
       * means that we are currently in the process of unstacking
       * it *and* there were some bytes waiting which are now
       * flushed. In this situation the pointer to the channel
       * itself already refers to the parent channel we have to
       * write the bytes into, so we return that.
       */
      return statePtr->self;
    }
    self = next;
  }

  return Tcl_GetStackedChannel (self);
#endif
}
