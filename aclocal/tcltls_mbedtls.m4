AC_DEFUN([TCLTLS_SSL_MBEDTLS], [
	mbedtlsdir=''
	AC_ARG_WITH([mbedtls-dir],
		AS_HELP_STRING(
			[--with-mbedtls-dir=<dir>],
			[path to root directory of MbedTLS installation]
		), [
			mbedtlsdir="$withval"
		]
	)

	if test -n "$mbedtlsdir"; then
		if test -e "$mbedtlsdir/libmbedtls.a" -o -e "$mbedtlsdir/libmbedtls.${AREXT}"; then
			TCLTLS_SSL_LIBS="-L$mbedtlsdir -lmbedtls -lmbedcrypto"
			mbedtlsdir="`AS_DIRNAME(["$mbedtlsdir"])`"
		else
			TCLTLS_SSL_LIBS="-L$mbedtlsdir/library -lmbedtls -lmbedcrypto"
		fi
		TCLTLS_SSL_CFLAGS="-I$mbedtlsdir/include -I${mbedtlsdir}/include/mbedtls"
		TCLTLS_SSL_CPPFLAGS="-I$mbedtlsdir/include -I${mbedtlsdir}/include/mbedtls"
	fi

	AC_ARG_VAR([TCLTLS_SSL_LIBS], [libraries to pass to the linker for MbedTLS])
	AC_ARG_VAR([TCLTLS_SSL_CFLAGS], [C compiler flags for MbedTLS])
	AC_ARG_VAR([TCLTLS_SSL_CPPFLAGS], [C preprocessor flags for MbedTLS])

	if test "$TCLEXT_BUILD" = "static"; then
		dnl If we are doing a static build, save the linker flags for other programs to consume
		rm -f tcltls.${AREXT}.linkadd
		AS_ECHO(["$TCLTLS_SSL_LIBS"]) > tcltls.${AREXT}.linkadd
	fi

	dnl If we have been asked to statically link to the SSL library, specifically tell the linker to do so
	if test "$TCLEXT_TLS_STATIC_SSL" = 'yes'; then
		dnl Don't bother doing this if we aren't actually doing the runtime linking
		if test "$TCLEXT_BUILD" != "static"; then
			dnl Split the libraries into SSL and non-SSL libraries
			new_TCLTLS_SSL_LIBS_normal=''
			new_TCLTLS_SSL_LIBS_static=''
			for arg in $TCLTLS_SSL_LIBS; do
				case "${arg}" in
					-L*)
						new_TCLTLS_SSL_LIBS_normal="${new_TCLTLS_SSL_LIBS_normal} ${arg}"
						new_TCLTLS_SSL_LIBS_static="${new_TCLTLS_SSL_LIBS_static} ${arg}"
						;;
					-ldl|-lrt|-lc|-lpthread|-lm|-lcrypt|-lidn|-lresolv|-lgcc|-lgcc_s)
						new_TCLTLS_SSL_LIBS_normal="${new_TCLTLS_SSL_LIBS_normal} ${arg}"
						;;
					-l*)
						new_TCLTLS_SSL_LIBS_static="${new_TCLTLS_SSL_LIBS_static} ${arg}"
						;;
					*)
						new_TCLTLS_SSL_LIBS_normal="${new_TCLTLS_SSL_LIBS_normal} ${arg}"
						;;
				esac
			done
			SHOBJ_DO_STATIC_LINK_LIB([MbedTLS], [$new_TCLTLS_SSL_LIBS_static], [new_TCLTLS_SSL_LIBS_static])
			TCLTLS_SSL_LIBS="${new_TCLTLS_SSL_LIBS_normal} ${new_TCLTLS_SSL_LIBS_static}"
		fi
	fi

	dnl Save compile-altering variables we are changing
	SAVE_LIBS="${LIBS}"
	SAVE_CFLAGS="${CFLAGS}"
	SAVE_CPPFLAGS="${CPPFLAGS}"

	dnl Update compile-altering variables to include the MbedTLS libraries
	LIBS="${TCLTLS_SSL_LIBS} ${SAVE_LIBS} ${TCLTLS_SSL_LIBS}"
	CFLAGS="${TCLTLS_SSL_CFLAGS} ${SAVE_CFLAGS} ${TCLTLS_SSL_CFLAGS}"
	CPPFLAGS="${TCLTLS_SSL_CPPFLAGS} ${SAVE_CPPFLAGS} ${TCLTLS_SSL_CPPFLAGS}"

	dnl Verify that basic functionality is there
	AC_LANG_PUSH(C)
	AC_MSG_CHECKING([if a basic MbedTLS program works])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([
#define MBEDTLS_CONFIG_FILE <mbedtls/config.h>
#include MBEDTLS_CONFIG_FILE
		], [
    mbedtls_ssl_context *ctx;
    mbedtls_ssl_init(ctx);
    mbedtls_ssl_setup(ctx, (void *) 0);
    mbedtls_ssl_free(ctx);
		])], [
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Unable to compile a basic program using MbedTLS])
	])
	AC_LANG_POP([C])

dnl
dnl	AC_CHECK_FUNCS([TLS_method])
dnl	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_ssl2], [SSLv2_method], [sslv2], [NO_SSL2])
dnl	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_ssl3], [SSLv3_method], [sslv3], [NO_SSL3])
dnl	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_0], [TLSv1_method], [tlsv1.0], [NO_TLS1])
dnl	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_1], [TLSv1_1_method], [tlsv1.1], [NO_TLS1_1])
dnl	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_2], [TLSv1_2_method], [tlsv1.2], [NO_TLS1_2])
dnl	TCLTLS_SSL_OPENSSL_CHECK_PROTO_VER([tcltls_ssl_tls1_3], [], [tlsv1.3], [NO_TLS1_3], [SSL_OP_NO_TLSv1_3])
dnl

	dnl Restore compile-altering variables
	LIBS="${SAVE_LIBS}"
	CFLAGS="${SAVE_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS}"
])
