AC_DEFUN([TCLTLS_SSL_OPENSSL], [
	AC_ARG_WITH([openssl-dir],
		AS_HELP_STRING(
			[--with-openssl-dir=<dir>],
			[path to root directory of OpenSSL or LibreSSL installation]
		), [
			if test -e "$withval/libssl.$SHOBJEXT"; then
				TCLTLS_SSL_LIBS="-L$withval -lssl -lcrypto"
				withval="`AS_DIRNAME(["$withval"])`"
			else
				TCLTLS_SSL_LIBS="-L$withval/lib -lssl -lcrypto"
			fi
			TCLTLS_SSL_CFLAGS="-I$withval/include"
			TCLTLS_SSL_CPPFLAGS="-I$withval/include"
		]
	)

	dnl Use pkg-config to find the libraries
	AC_ARG_VAR([TCLTLS_SSL_LIBS], [libraries to pass to the linker for OpenSSL or LibreSSL])
	AC_ARG_VAR([TCLTLS_SSL_CFLAGS], [C compiler flags for OpenSSL or LibreSSL])
	AC_ARG_VAR([TCLTLS_SSL_CPPFLAGS], [C preprocessor flags for OpenSSL or LibreSSL])
	if test -z "$TCLTLS_SSL_LIBS"; then
		TCLTLS_SSL_LIBS="`"${PKGCONFIG}" openssl --libs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	fi
	if test -z "$TCLTLS_SSL_CFLAGS"; then
		TCLTLS_SSL_CFLAGS="`"${PKGCONFIG}" openssl --cflags-only-other`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	fi
	if test -z "$TCLTLS_SSL_CPPFLAGS"; then
		TCLTLS_SSL_CPPFLAGS="`"${PKGCONFIG}" openssl --cflags-only-I`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	fi

	dnl Save compile-altering variables we are changing
	SAVE_LIBS="${LIBS}"
	SAVE_CFLAGS="${CFLAGS}"
	SAVE_CPPFLAGS="${CPPFLAGS}"

	dnl Update compile-altering variables to include the OpenSSL libraries
	LIBS="${SAVE_LIBS} ${TCLTLS_SSL_LIBS}"
	CFLAGS="${SAVE_CFLAGS} ${TCLTLS_SSL_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS} ${TCLTLS_SSL_CPPFLAGS}"

	dnl Verify that basic functionality is there
	AC_LANG_PUSH(C)
	AC_MSG_CHECKING([if a basic OpenSSL program works])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <openssl/ssl.h>
#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#endif
		], [
  (void)SSL_library_init();
  SSL_load_error_strings();
  OPENSSL_config(NULL);
		])], [
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Unable to compile a basic program using OpenSSL])
	])
	AC_LANG_POP([C])

	dnl Determine if SSLv2 is supported
	if test "$tcltls_ssl_ssl2" = "true"; then
		AC_CHECK_FUNC(SSLv2_method,, [
			tcltls_ssl_ssl2='false'
		])
	fi

	if test "$tcltls_ssl_ssl2" = "false"; then
		AC_DEFINE(NO_SSL2, [1], [Define this to disable SSLv2 in OpenSSL support])
	fi

	dnl Determine if SSLv3 is supported
	if test "$tcltls_ssl_ssl3" = "true"; then
		AC_CHECK_FUNC(SSLv3_method,, [
			tcltls_ssl_ssl3='false'
		])
	fi

	if test "$tcltls_ssl_ssl3" = "false"; then
		AC_DEFINE(NO_SSL3, [1], [Define this to disable SSLv3 in OpenSSL support])
	fi

	dnl Determine if TLSv1.0 is supported
	if test "$tcltls_ssl_tls1_0" = "true"; then
		AC_CHECK_FUNC(TLSv1_method,, [
			tcltls_ssl_tls1_0='false'
		])
	fi

	if test "$tcltls_ssl_tls1_0" = "false"; then
		AC_DEFINE(NO_TLS1, [1], [Define this to disable TLSv1.0 in OpenSSL support])
	fi

	dnl Determine if TLSv1.1 is supported
	if test "$tcltls_ssl_tls1_1" = "true"; then
		AC_CHECK_FUNC(TLSv1_1_method,, [
			tcltls_ssl_tls1_1='false'
		])
	fi

	if test "$tcltls_ssl_tls1_1" = "false"; then
		AC_DEFINE(NO_TLS1_1, [1], [Define this to disable TLSv1.1 in OpenSSL support])
	fi

	dnl Determine if TLSv1.2 is supported
	if test "$tcltls_ssl_tls1_2" = "true"; then
		AC_CHECK_FUNC(TLSv1_2_method,, [
			tcltls_ssl_tls1_2='false'
		])
	fi

	if test "$tcltls_ssl_tls1_2" = "false"; then
		AC_DEFINE(NO_TLS1_2, [1], [Define this to disable TLSv1.2 in OpenSSL support])
	fi

	dnl Restore compile-altering variables
	LIBS="${SAVE_LIBS}"
	CFLAGS="${SAVE_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS}"
])
