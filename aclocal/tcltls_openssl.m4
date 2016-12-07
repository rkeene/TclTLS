dnl $1 = Name of variable
dnl $2 = Name of function to check for
dnl $3 = Name of protocol
dnl $4 = Name of CPP macro to define
AC_DEFUN([TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER], [
	dnl Determine if particular SSL version is enabled
	if test "[$]$1" = "true" -o "[$]$1" = "force"; then
		AC_CHECK_FUNC($2,, [
			if test "[$]$1" = "force"; then
				AC_MSG_ERROR([Unable to enable $3])
			fi

			$1='false'
		])
	fi

	if test "[$]$1" = "false"; then
		AC_DEFINE($4, [1], [Define this to disable $3 in OpenSSL support])
	fi

])

AC_DEFUN([TCLTLS_SSL_OPENSSL], [
	openssldir=''
	AC_ARG_WITH([ssl-dir],
		AS_HELP_STRING(
			[--with-ssl-dir=<dir>],
			[deprecated, use --with-openssl-dir -- currently has the same meaning]
		), [
			openssldir="$withval"
		]
	)
	AC_ARG_WITH([openssl-dir],
		AS_HELP_STRING(
			[--with-openssl-dir=<dir>],
			[path to root directory of OpenSSL or LibreSSL installation]
		), [
			openssldir="$withval"
		]
	)

	if test -n "$openssldir"; then
		if test -e "$openssldir/libssl.$SHOBJEXT"; then
			TCLTLS_SSL_LIBS="-L$openssldir -lssl -lcrypto"
			openssldir="`AS_DIRNAME(["$openssldir"])`"
		else
			TCLTLS_SSL_LIBS="-L$openssldir/lib -lssl -lcrypto"
		fi
		TCLTLS_SSL_CFLAGS="-I$openssldir/include"
		TCLTLS_SSL_CPPFLAGS="-I$openssldir/include"
	fi

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

	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_ssl2], [SSLv2_method], [sslv2], [NO_SSL2])
	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_ssl3], [SSLv3_method], [sslv3], [NO_SSL3])
	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_0], [TLSv1_method], [tlsv1.0], [NO_TLS1])
	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_1], [TLSv1_1_method], [tlsv1.1], [NO_TLS1_1])
	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_2], [TLSv1_2_method], [tlsv1.2], [NO_TLS1_2])

	AC_CACHE_VAL([tcltls_cv_func_tlsext_hostname], [
		AC_LANG_PUSH(C)
		AC_MSG_CHECKING([for SSL_set_tlsext_host_name])
		AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <openssl/ssl.h>
#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#endif
			], [
  (void)SSL_set_tlsext_host_name((void *) 0, (void *) 0);
			])], [
			AC_MSG_RESULT([yes])
			tcltls_cv_func_tlsext_hostname='yes'
			tcltls_cv_func_tlsext_hostname='no'
		], [
			AC_MSG_RESULT([no])
		])
		AC_LANG_POP([C])

dnl		AC_CHECK_FUNC(SSL_set_tlsext_host_name, [
dnl		], [
dnl		])
	])

	if test "$tcltls_cv_func_tlsext_hostname" = 'no'; then
		AC_DEFINE([OPENSSL_NO_TLSEXT], [1], [Define this if your OpenSSL does not support the TLS Extension for SNI])
	fi

	dnl Restore compile-altering variables
	LIBS="${SAVE_LIBS}"
	CFLAGS="${SAVE_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS}"
])
