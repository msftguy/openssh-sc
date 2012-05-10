/*
 * Copyright (c) 2002-2007,2011 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "x509store.h"
#include <openssl/x509v3.h>
#include "log.h"

#ifndef SSH_X509STORE_DISABLED
#include <string.h>

#include "xmalloc.h"
#include "pathnames.h"
#include "misc.h"
#include <openssl/x509_vfy.h>
/* struct X509_VERIFY_PARAM is defined in OpenSSL 0.9.8x */
#ifdef HAVE_X509_STORE_CTX_PARAM
#  define SSH_X509_VERIFY_PARAM(ctx,member) ctx->param->member
#else
#  define SSH_X509_VERIFY_PARAM(ctx,member) ctx->member
#endif
#ifdef LDAP_ENABLED
#  include "x509_by_ldap.h"
#endif
#endif /*ndef SSH_X509STORE_DISABLED*/


SSH_X509Flags
ssh_x509flags = {
	0,	/* is_server */
	-1,	/* allowedcertpurpose */
#ifndef SSH_X509STORE_DISABLED
	-1,	/* key_allow_selfissued */
	-1	/* mandatory_crl */
#endif /*ndef SSH_X509STORE_DISABLED*/
};


#ifndef SSH_X509STORE_DISABLED
static X509_STORE	*x509store = NULL;
#if OPENSSL_VERSION_NUMBER < 0x00907000L
/* void X509_STORE_CTX_init() */
static int ssh_X509_STORE_CTX_init (
	X509_STORE_CTX *ctx,
	X509_STORE *store,
	X509 *x509,
	STACK_OF(X509) *chain)
{
	X509_STORE_CTX_init(ctx, store, x509, chain);
	return(1);
}

#define X509_STORE_CTX_init ssh_X509_STORE_CTX_init
#endif

#if 1
#  define SSH_CHECK_REVOKED
#endif


#ifdef SSH_CHECK_REVOKED
static X509_STORE	*x509revoked = NULL;
static int ssh_x509revoked_cb(int ok, X509_STORE_CTX *ctx);


static char *
ssh_ASN1_INTEGER_2_string(ASN1_INTEGER *_asni) {
	BIO  *bio;
	int   k;
	char *p;

	if (_asni == NULL) {
		error("ssh_ASN1_INTEGER_2_string: _asni is NULL");
		return(NULL);
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		fatal("ssh_ASN1_INTEGER_2_string: out of memory");
		return(NULL); /* ;-) */
	}

	i2a_ASN1_INTEGER(bio, _asni);
	k = BIO_pending(bio);
	p = xmalloc(k + 1); /*fatal on error*/
	k = BIO_read(bio, p, k);
	p[k] = '\0';
	BIO_free_all(bio);

	return(p);
}
#endif /*def SSH_CHECK_REVOKED*/


int
ssh_x509store_lookup(X509_STORE *store, int type, X509_NAME *name, X509_OBJECT *xobj) {
	X509_STORE_CTX ctx;
	int ret;

	if (X509_STORE_CTX_init(&ctx, store, NULL, NULL) <= 0) {
		/*memory allocation error*/
		error("ssh_x509store_lookup: cannot initialize x509store context");
		return(-1);
	}
	ret = X509_STORE_get_by_subject(&ctx, type, name, xobj);
	X509_STORE_CTX_cleanup(&ctx);

	return(ret);
}


static int
ssh_x509store_cb(int ok, X509_STORE_CTX *ctx) {
	int ctx_error = X509_STORE_CTX_get_error(ctx);
	X509 *ctx_cert = X509_STORE_CTX_get_current_cert(ctx);
	int self_signed = 0;

	if ((!ok) &&
	    (ctx_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	) {
		if (ssh_x509flags.key_allow_selfissued) {
			ok = ssh_is_selfsigned(ctx_cert);
			if (ok)
				self_signed = 1;
		}
	}
	if (!ok) {
		char *buf;
		buf = ssh_X509_NAME_oneline(X509_get_subject_name(ctx_cert)); /*fatal on error*/
		error("ssh_x509store_cb: subject='%s', error %d at %d depth lookup:%.200s",
			buf,
			ctx_error,
			X509_STORE_CTX_get_error_depth(ctx),
			X509_verify_cert_error_string(ctx_error));
		xfree(buf);
	}
#ifdef SSH_CHECK_REVOKED
	if (ok && !self_signed) {
		ok = ssh_x509revoked_cb(ok, ctx);
	}
#endif
	return(ok);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


typedef struct  {
	const char **synonyms;
}	CertPurposes;


static const char *__purpose_any[] = {
	"any", "any purpose", "any_purpose", "anypurpose", NULL
};


static const char *__purpose_sslclient[] = {
	"sslclient", "ssl client", "ssl_client", "client", NULL
};


static const char *__purpose_sslserver[] = {
	"sslserver", "ssl server", "ssl_server", "server", NULL
};


static CertPurposes
sslclient_purposes[] = {
	{ __purpose_sslclient },
	{ __purpose_any },
	{ NULL }
};


static CertPurposes
sslserver_purposes [] = {
	{ __purpose_sslserver },
	{ __purpose_any },
	{ NULL }
};


static const char*
get_cert_purpose(const char* _purpose_synonym, CertPurposes *_purposes) {
	int i;

	for (i = 0; _purposes[i].synonyms; i++) {
		const char *q = _purposes[i].synonyms[0];
		if (strcasecmp(_purpose_synonym, q) == 0 ) {
			return(q);
		} else {
			const char **p;
			for (p = (_purposes[i].synonyms) + 1; *p; p++) {
				if (strcasecmp(_purpose_synonym, *p) == 0 ) {
					return(q);
				}
			}
		}
	}
	return(NULL);
}


void
ssh_x509flags_initialize(SSH_X509Flags *flags, int is_server) {
	flags->is_server = is_server;
	flags->allowedcertpurpose = -1;
#ifndef SSH_X509STORE_DISABLED
	flags->key_allow_selfissued = -1;
	flags->mandatory_crl = -1;
#endif /*ndef SSH_X509STORE_DISABLED*/
}


void
ssh_x509flags_defaults(SSH_X509Flags *flags) {
	if (flags->allowedcertpurpose == -1) {
		int is_server = flags->is_server;
		const char* purpose_synonym = is_server ? __purpose_sslclient[0] : __purpose_sslserver[0];

		flags->allowedcertpurpose = ssh_get_x509purpose_s(is_server, purpose_synonym);
	}
#ifndef SSH_X509STORE_DISABLED
	if (flags->key_allow_selfissued == -1) {
		flags->key_allow_selfissued = 0;
	}
#ifdef SSH_CHECK_REVOKED
	if (flags->mandatory_crl == -1) {
		flags->mandatory_crl = 0;
	}
#else
	if (flags->mandatory_crl != -1) {
		logit("useless option: mandatory_crl");
	}
#endif
#endif /*ndef SSH_X509STORE_DISABLED*/
}


int
ssh_get_x509purpose_s(int _is_server, const char* _purpose_synonym) {
	const char * sslpurpose;

	sslpurpose = get_cert_purpose(_purpose_synonym,
		(_is_server ? sslclient_purposes : sslserver_purposes));
	if (sslpurpose != NULL) {
		int purpose_index = X509_PURPOSE_get_by_sname((char*)sslpurpose);
		if (purpose_index  < 0)
			fatal(	"ssh_get_x509purpose_s(%.10s): "
				"X509_PURPOSE_get_by_sname fail for argument '%.30s(%.40s)'",
				(_is_server ? "server" : "client"),
				sslpurpose, _purpose_synonym);
		return(purpose_index);
	}
	return(-1);
}


#ifndef SSH_X509STORE_DISABLED
int/*bool*/
ssh_is_selfsigned(X509 *_cert) {
#ifdef EXFLAG_SS
  /* OpenSSL 0.9.7+ */
  #if 0
    #define USE_EXFLAG_SS
  #endif
#endif
#ifdef USE_EXFLAG_SS
	X509_check_purpose(_cert, -1, 0); /* set flags */
	return (_cert->ex_flags & EXFLAG_SS) != 0;
#else
	X509_NAME *issuer, *subject;

	issuer  = X509_get_issuer_name(_cert);
	subject = X509_get_subject_name(_cert);

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf;

		buf = ssh_X509_NAME_oneline(issuer);  /*fatal on error*/
		debug3("ssh_is_selfsigned: issuer='%s'", buf);
		xfree(buf);

		buf = ssh_X509_NAME_oneline(subject); /*fatal on error*/
		debug3("ssh_is_selfsigned: subject='%s'", buf);
		xfree(buf);
	}

	return (ssh_X509_NAME_cmp(issuer, subject) == 0);
#endif
}


void
ssh_x509store_initialize(X509StoreOptions *options) {
	options->certificate_file = NULL;
	options->certificate_path = NULL;
	options->revocation_file = NULL;
	options->revocation_path = NULL;
#ifdef LDAP_ENABLED
	options->ldap_ver = NULL;
	options->ldap_url = NULL;
#endif
}


void
ssh_x509store_system_defaults(X509StoreOptions *options) {
	if (options->certificate_file == NULL)
		options->certificate_file = _PATH_CA_CERTIFICATE_FILE;
	if (options->certificate_path == NULL)
		options->certificate_path = _PATH_CA_CERTIFICATE_PATH;
	if (options->revocation_file == NULL)
		options->revocation_file = _PATH_CA_REVOCATION_FILE;
	if (options->revocation_path == NULL)
		options->revocation_path = _PATH_CA_REVOCATION_PATH;
#ifdef LDAP_ENABLED
	/*nothing to do ;-)*/
#endif
}


static void
tilde_expand_filename2(const char **_fn, const char* _default, uid_t uid) {
	if (*_fn == NULL) {
		*_fn = tilde_expand_filename(_default, uid);
	} else {
		const char *p = *_fn;
		*_fn = tilde_expand_filename(p, uid);
		xfree((void*)p);
	}
}


void
ssh_x509store_user_defaults(X509StoreOptions *options, uid_t uid) {
	tilde_expand_filename2(&options->certificate_file, _PATH_USERCA_CERTIFICATE_FILE, uid);
	tilde_expand_filename2(&options->certificate_path, _PATH_USERCA_CERTIFICATE_PATH, uid);
	tilde_expand_filename2(&options->revocation_file , _PATH_USERCA_REVOCATION_FILE , uid);
	tilde_expand_filename2(&options->revocation_path , _PATH_USERCA_REVOCATION_PATH , uid);
#ifdef LDAP_ENABLED
	/*nothing to do ;-)*/
#endif
}


static void
ssh_x509store_initcontext(void) {
	if (x509store == NULL) {
		x509store = X509_STORE_new();
		if (x509store == NULL) {
			fatal("cannot create x509store context");
		}
		X509_STORE_set_verify_cb_func(x509store, ssh_x509store_cb);
	}
#ifdef SSH_CHECK_REVOKED
	if (x509revoked == NULL) {
		x509revoked = X509_STORE_new();
		if (x509revoked == NULL) {
			fatal("cannot create x509revoked context");
		}
	}
#endif
}


int/*bool*/
ssh_x509store_addlocations(const X509StoreOptions *_locations) {
	int flag;

	if (_locations == NULL) {
		error("ssh_x509store_addlocations: _locations is NULL");
		return(0);
	}
	if ((_locations->certificate_path == NULL) &&
	    (_locations->certificate_file == NULL)) {
		error("ssh_x509store_addlocations: certificate path and file are NULLs");
		return(0);
	}
#ifdef SSH_CHECK_REVOKED
	if ((_locations->revocation_path == NULL) &&
	    (_locations->revocation_file == NULL)) {
		error("ssh_x509store_addlocations: revocation path and file are NULLs");
		return(0);
	}
#endif
	ssh_x509store_initcontext();

	flag = 0;
	/*
	 * Note:
	 * After X509_LOOKUP_{add_dir|load_file} calls we must call
	 * ERR_clear_error() otherwise when the first call to
	 * X509_LOOKUP_XXXX fail the second call fail too !
	 */
	if (_locations->certificate_path != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509store, X509_LOOKUP_hash_dir());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add hash dir lookup !");
			return(0); /* ;-) */
		}
		if (X509_LOOKUP_add_dir(lookup, _locations->certificate_path, X509_FILETYPE_PEM)) {
			debug2("hash dir '%.400s' added to x509 store", _locations->certificate_path);
			flag = 1;
		}
		ERR_clear_error();
	}
	if (_locations->certificate_file != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509store, X509_LOOKUP_file());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add file lookup !");
			return(0); /* ;-) */
		}
		if (X509_LOOKUP_load_file(lookup, _locations->certificate_file, X509_FILETYPE_PEM)) {
			debug2("file '%.400s' added to x509 store", _locations->certificate_file);
			flag = 1;
		}
		ERR_clear_error();
	}
	/*at least one lookup should succeed*/
	if (flag == 0) return(0);

	flag = 0;
#ifdef SSH_CHECK_REVOKED
	if (_locations->revocation_path != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509revoked, X509_LOOKUP_hash_dir());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add hash dir revocation lookup !");
			return(0); /* ;-) */
		}
		if (X509_LOOKUP_add_dir(lookup, _locations->revocation_path, X509_FILETYPE_PEM)) {
			debug2("hash dir '%.400s' added to x509 revocation store", _locations->revocation_path);
			flag = 1;
		}
		ERR_clear_error();
	}
	if (_locations->revocation_file != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509revoked, X509_LOOKUP_file());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add file revocation lookup !");
			return(0); /* ;-) */
		}
		if (X509_LOOKUP_load_file(lookup, _locations->revocation_file, X509_FILETYPE_PEM)) {
			debug2("file '%.400s' added to x509 revocation store", _locations->revocation_file);
			flag = 1;
		}
		ERR_clear_error();
	}
#else /*ndef SSH_CHECK_REVOKED*/
	if (_locations->revocation_path != NULL) {
		logit("useless option: revocation_path");
	}
	if (_locations->revocation_file != NULL) {
		logit("useless option: revocation_file");
	}
	flag = 1;
#endif /*ndef SSH_CHECK_REVOKED*/
	/*at least one revocation lookup should succeed*/
	if (flag == 0) return(0);

#ifdef LDAP_ENABLED
	if (_locations->ldap_url != NULL) {
		X509_LOOKUP *lookup;

		lookup = X509_STORE_add_lookup(x509store, X509_LOOKUP_ldap());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add ldap lookup !");
			return(0); /* ;-) */
		}
		if (X509_LOOKUP_add_ldap(lookup, _locations->ldap_url)) {
			debug2("ldap url '%.400s' added to x509 store", _locations->ldap_url);
		}
		if (_locations->ldap_ver != NULL) {
			if (!X509_LOOKUP_set_protocol(lookup, _locations->ldap_ver)) {
				fatal("ssh_x509store_addlocations: cannot set ldap version !");
				return(0); /* ;-) */
			}
		}
		/*ERR_clear_error();*/

#ifdef SSH_CHECK_REVOKED
		lookup = X509_STORE_add_lookup(x509revoked, X509_LOOKUP_ldap());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add ldap lookup(revoked) !");
			return(0); /* ;-) */
		}
		if (X509_LOOKUP_add_ldap(lookup, _locations->ldap_url)) {
			debug2("ldap url '%.400s' added to x509 store(revoked)", _locations->ldap_url);
		}
		if (_locations->ldap_ver != NULL) {
			if (!X509_LOOKUP_set_protocol(lookup, _locations->ldap_ver)) {
				fatal("ssh_x509store_addlocations: cannot set ldap version(revoked) !");
				return(0); /* ;-) */
			}
		}
		/*ERR_clear_error();*/
#endif /*def SSH_CHECK_REVOKED*/
	}
#endif /*def LDAP_ENABLED*/

	return(1);
}


static int
ssh_verify_cert(X509_STORE_CTX *_csc, X509 *_cert) {
	int flag;
	if (X509_STORE_CTX_init(_csc, x509store, _cert, NULL) <= 0) {
		/*memory allocation error*/
		error("ssh_verify_cert: cannot initialize x509store context");
		return(-1);
	}

	if (ssh_x509flags.allowedcertpurpose >= 0) {
		int def_purpose =  ( ssh_x509flags.is_server
			? X509_PURPOSE_SSL_CLIENT
			: X509_PURPOSE_SSL_SERVER
		);
		X509_PURPOSE *xptmp = X509_PURPOSE_get0(ssh_x509flags.allowedcertpurpose);
		int purpose;
		if (xptmp == NULL) {
			fatal("ssh_verify_cert: cannot get purpose from index");
			return(-1); /* ;-) */
		}
		purpose = X509_PURPOSE_get_id(xptmp);
		flag = X509_STORE_CTX_purpose_inherit(_csc, def_purpose, purpose, 0);
		if (flag <= 0) {
			/*
			 * By default openssl applications don't check return code from
			 * X509_STORE_CTX_set_purpose or X509_STORE_CTX_purpose_inherit.
			 *
			 * Both methods return 0 (zero) and don't change purpose in context when:
			 * -X509_STORE_CTX_set_purpose(...)
			 *   purpose is X509_PURPOSE_ANY
			 * -X509_STORE_CTX_purpose_inherit(...)
			 *   purpose is X509_PURPOSE_ANY and default purpose is zero (!)
			 *
			 * Take note when purpose is "any" check method in current
			 * OpenSSL code just return 1. This openssl behavior is same
			 * as ssh option "AllowedCertPurpose=skip".
			 */
			int ecode;
			char ebuf[256];

			ecode = X509_STORE_CTX_get_error(_csc);
			error("ssh_verify_cert: context purpose error, code=%d, msg='%.200s'"
				, ecode
				, X509_verify_cert_error_string(ecode));

			openssl_errormsg(ebuf, sizeof(ebuf));
			error("ssh_verify_cert: X509_STORE_CTX_purpose_inherit failed with '%.256s'"
				, ebuf);
			return(-1);
		}
	}

	/*
	if (issuer_checks)
		X509_STORE_CTX_set_flags(_csc, X509_V_FLAG_CB_ISSUER_CHECK);
	*/

	flag = X509_verify_cert(_csc);
	if (flag < 0) {
		/* NOTE: negative result is returned only if certificate to check
		 * is not set in context. This function is called if _cert is non
		 * NULL, i.e. certificate has to be set in context!
		 * Lets log (posible in future) cases with negative value.
		 */
		logit("ssh_verify_cert: X509_verify_cert return unexpected negative value: '%d'", flag);
		return(-1);
	}
	if (flag == 0) {
		int ecode = X509_STORE_CTX_get_error(_csc);
		error("ssh_verify_cert: verify error, code=%d, msg='%.200s'"
			, ecode
			, X509_verify_cert_error_string(ecode));
		return(-1);
	}

	return(1);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


int
ssh_x509cert_check(X509 *_cert) {
	int ret = 1;
#ifndef SSH_X509STORE_DISABLED
	X509_STORE_CTX *csc;
#else /*def SSH_X509STORE_DISABLED*/
	X509_PURPOSE *xptmp;
#endif /*def SSH_X509STORE_DISABLED*/

#ifndef SSH_X509STORE_DISABLED
	if (_cert == NULL) {
		/*already checked but ...*/
		error("ssh_x509cert_check: cert is NULL");
		ret = -1;
		goto done;
	}
	if (x509store == NULL) {
		error("ssh_x509cert_check: context is NULL");
		ret = -1;
		goto done;
	}

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf;
		buf = ssh_X509_NAME_oneline(X509_get_subject_name(_cert)); /*fatal on error*/
		debug3("ssh_x509cert_check: for '%s'", buf);
		xfree(buf);
	}

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		char ebuf[256];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("ssh_x509cert_check: X509_STORE_CTX_new failed with '%.*s'",
		      (int)sizeof(ebuf), ebuf);
		ret = -1;
		goto done;
	}

	ret = ssh_verify_cert(csc, _cert);
	X509_STORE_CTX_free(csc);
#ifdef SSH_OCSP_ENABLED
	if (ret > 0) {
/*
 * OpenSSH implementation first verify and validate certificate by
 * "X.509 store" with certs and crls from file system. It is fast
 * check. After this when certificate chain is correct and
 * certificate is not revoked we send a status request to an OCSP
 * responder if configured.
 *
 * RFC2560(OCSP):
 * ...
 * 2.7 CA Key Compromise
 * If an OCSP responder knows that a particular CA's private key
 * has been compromised, it MAY return the revoked state for all
 * certificates issued by that CA.
 * ...
 * 5. Security Considerations
 * For this service to be effective, certificate using systems must
 * connect to the certificate status service provider. In the event
 * such a connection cannot be obtained, certificate-using systems
 * could implement CRL processing logic as a fall-back position.
 * ...
 * RFC2560(OCSP)^
 *
 * About OpenSSH implementation:
 * 1.) We preffer to delegate validation of issuer certificates to
 * 'OCSP Provider'. It is easy and simple to configure an OCSP
 * responder to return revoked state for all certificates issued
 * by a CA. Usually 'OCSP Provider' admins shall be first informed
 * for certificates with changed state. In each case this simplify
 * 'OCSP client'.
 * 2.) To conform to RFC2560 we should use OCSP to check status of
 * all certificates in the chain. Since this is network request it
 * is good to implement a cache and to save status with lifetime.
 * Might is good to have an OCSP cache server ;-).
 *
 * To minimize network latency and keeping in mind 1.) we send
 * 'OCSP request' only for the last certificate in the chain, i.e.
 * sended client or server certificate.
 *
 * Therefore instead to send OCSP request in ssh_x509revoked_cb()
 * we do this here.
 */
		ret = ssh_ocsp_validate(_cert, x509store);
	}
#endif /*def SSH_OCSP_ENABLED*/

#else /*def SSH_X509STORE_DISABLED*/
	if (ssh_x509flags.allowedcertpurpose >= 0) {
		xptmp = X509_PURPOSE_get0(ssh_x509flags.allowedcertpurpose);
		if (xptmp == NULL) {
			fatal("ssh_x509cert_check: cannot get purpose from index");
			return(-1); /* ;-) */
		}
		ret = X509_check_purpose(_cert, X509_PURPOSE_get_id(xptmp), 0);
		if (ret < 0) {
			logit("ssh_x509cert_check: X509_check_purpose return %d", ret);
			ret = 0;
		}
	}
#endif /*def SSH_X509STORE_DISABLED*/
done:
{
	const char *msg = (ret > 0) ? "trusted" : (ret < 0 ? "error" : "rejected");
	debug3("ssh_x509cert_check: return %d(%s)", ret, msg);
}
	return(ret);
}


#ifndef SSH_X509STORE_DISABLED
#ifdef SSH_CHECK_REVOKED
static void
ssh_get_namestr_and_hash(
	X509_NAME *name,
	char **buf,
	u_long *hash
) {
	if (name == NULL) {
		debug("ssh_get_namestr_and_hash: name is NULL");
		if (buf ) *buf  = NULL;
		if (hash) *hash = 0; /* not correct but :-( */
		return;
	}

	if (buf ) *buf  = ssh_X509_NAME_oneline(name); /*fatal on error*/
	if (hash) *hash = X509_NAME_hash(name);
}


static int/*bool*/
ssh_check_crl(X509_STORE_CTX *_ctx, X509* _issuer, X509_CRL *_crl) {
	time_t *pcheck_time;
	int     k;
	u_long hash;

	if (_issuer == NULL) {
		error("ssh_check_crl: issuer is NULL");
		return(0);
	}
	if (_crl == NULL) {
		debug("ssh_check_crl: crl is NULL");
		return(1);
	}

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		BIO *bio;
		char *p;

		bio = BIO_new(BIO_s_mem());
		if (bio == NULL) {
			fatal("ssh_check_crl: out of memory");
			return(0); /* ;-) */
		}

		ssh_X509_NAME_print(bio, X509_CRL_get_issuer(_crl));

		BIO_printf(bio, "; Last Update: ");
		ASN1_UTCTIME_print(bio, X509_CRL_get_lastUpdate(_crl));

		BIO_printf(bio, "; Next Update: ");
		ASN1_UTCTIME_print(bio, X509_CRL_get_nextUpdate(_crl));

		k = BIO_pending(bio);
		p = xmalloc(k + 1); /*fatal on error*/
		k = BIO_read(bio, p, k);
		p[k] = '\0';

		debug3("ssh_check_crl: Issuer: %s", p);

		xfree(p);
		BIO_free(bio);
	}

/* RFC 3280:
 * The cRLSign bit is asserted when the subject public key is used
 * for verifying a signature on certificate revocation list (e.g., a
 * CRL, delta CRL, or an ARL).  This bit MUST be asserted in
 * certificates that are used to verify signatures on CRLs.
 */
	if (/*???(_issuer->ex_flags & EXFLAG_KUSAGE) &&*/
	    !(_issuer->ex_kusage & KU_CRL_SIGN)
	) {
		char *buf;
	#ifdef X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
		/*first defined in OpenSSL 0.9.7d*/
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_KEYUSAGE_NO_CRL_SIGN);
	#endif
		ssh_get_namestr_and_hash(X509_get_subject_name(_issuer), &buf, &hash);
		error("ssh_check_crl:"
			" to verify crl signature key usage 'cRLSign'"
			" must present in issuer certificate '%s' with hash=0x%08lx"
			, buf, hash
		);
		xfree(buf);
		return(0);
	}

	{
		EVP_PKEY *pkey = X509_get_pubkey(_issuer);
		if (pkey == NULL) {
			error("ssh_check_crl: unable to decode issuer public key");
			X509_STORE_CTX_set_error(_ctx, X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
			return(0);
		}

		if (X509_CRL_verify(_crl, pkey) <= 0) {
			char *buf;

			ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
			error("ssh_check_crl: CRL has invalid signature"
				": issuer='%s', hash=0x%08lx"
				, buf, hash
			);
			X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
			xfree(buf);
			return(0);
		}
		EVP_PKEY_free(pkey);
	}


	if (SSH_X509_VERIFY_PARAM(_ctx,flags) & X509_V_FLAG_USE_CHECK_TIME)
		pcheck_time = &SSH_X509_VERIFY_PARAM(_ctx,check_time);
	else
		pcheck_time = NULL;

	k = X509_cmp_time(X509_CRL_get_lastUpdate(_crl), pcheck_time);
	if (k == 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL has invalid lastUpdate field"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD);
		xfree(buf);
		return(0);
	}
	if (k > 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL is not yet valid"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CRL_NOT_YET_VALID);
		xfree(buf);
		return(0);
	}

	k = X509_cmp_time(X509_CRL_get_nextUpdate(_crl), pcheck_time);
	if (k == 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL has invalid nextUpdate field"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
		xfree(buf);
		return(0);
	}
#if 0
	/*test "extend time limit"*/
	if (k < 0) {
		time_t	tm;
		if (pcheck_time == NULL) {
			tm = time(NULL);
			pcheck_time = &tm;
		}
		*pcheck_time -= convtime("1w");
		k = X509_cmp_time(X509_CRL_get_nextUpdate(_crl), pcheck_time);
	}
#endif
	if (k < 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL is expired"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
		xfree(buf);
		return(0);
	}

	return(1);
}


static int/*bool*/
ssh_is_cert_revoked(X509_STORE_CTX *_ctx, X509_CRL *_crl, X509 *_cert) {
	X509_REVOKED revoked;
	int   k;
	char *dn, *ser, *in;

	if (_crl == NULL) return(1);
	revoked.serialNumber = X509_get_serialNumber(_cert);
	k = sk_X509_REVOKED_find(_crl->crl->revoked, &revoked);
	if (k < 0) return(0);

	X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CERT_REVOKED);
	/* yes, revoked. print log and ...*/
	dn  = ssh_X509_NAME_oneline(X509_get_subject_name(_cert)); /*fatal on error*/
	ser = ssh_ASN1_INTEGER_2_string(revoked.serialNumber);
	in  = ssh_X509_NAME_oneline(X509_CRL_get_issuer  (_crl )); /*fatal on error*/

	error("certificate '%s' with serial '%.40s' revoked from issuer '%s'"
		, dn, ser, in);
	xfree(dn);
	xfree(ser);
	xfree(in);

	return(1);
}


static int
ssh_x509revoked_cb(int ok, X509_STORE_CTX *ctx) {
	X509        *cert;
	X509_OBJECT  xobj;

	if (!ok) return(0);
	if (x509revoked == NULL)
		return(ok); /* XXX:hmm */

	cert = X509_STORE_CTX_get_current_cert(ctx);
	if (cert == NULL) {
		error("ssh_x509revoked_cb: missing current certificate in x509store context");
		return(0);
	}

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf;

		buf = ssh_X509_NAME_oneline(X509_get_issuer_name(cert)); /*fatal on error*/
		debug3("ssh_x509revoked_cb: Issuer: %s", buf);
		xfree(buf);

		buf = ssh_X509_NAME_oneline(X509_get_subject_name(cert)); /*fatal on error*/
		debug3("ssh_x509revoked_cb: Subject: %s", buf);
		xfree(buf);
	}

	memset(&xobj, 0, sizeof(xobj));
/* TODO:
 * NID_crl_distribution_points may contain one or more
 * CRLissuer != cert issuer
 */
	if (ssh_x509store_lookup(
	      x509revoked, X509_LU_CRL,
	      X509_get_subject_name(cert),
	      &xobj) > 0) {
/*
 * In callback we cannot check CRL signature at this point when we use
 * X509_get_issuer_name(), because we don't know issuer public key!
 * Of course we can get the public key from X509_STORE defined by
 * static variable "x509store".
 * Of course we can check revocation outside callback, but we should
 * try to find public key in X509_STORE[s].
 *
 * At this point we can get easy public key of "current certificate"!
 *
 * Method: "look forward"
 * At this call we check CLR (signature and other) issued with "current
 * certificate" ("CertA"). If all is OK with "CertA" by next call of
 * callback method "current certificate" is signed from "CertA" and the
 * CRL issued from "CertA", if any is already verified - cool ;-).
 *
 * Note that when a certificate is revoked all signed form that
 * certificate are revoked automatically too. With method "look forward"
 * we already know that all issuers of "current certificate" aren't
 * revoked.
 */
		ok = ssh_check_crl(ctx, cert, xobj.data.crl);
	} else {
		if (ssh_x509flags.mandatory_crl == 1) {
			int loc;
			loc = X509_get_ext_by_NID(cert, NID_crl_distribution_points, -1);
			ok = (loc < 0);
			if (!ok) {
				error("ssh_x509revoked_cb: unable to get issued CRL");
				X509_STORE_CTX_set_error(ctx, X509_V_ERR_UNABLE_TO_GET_CRL);
			}
		}
	}
	X509_OBJECT_free_contents(&xobj);
	if (!ok) return(0);

	memset(&xobj, 0, sizeof(xobj));
	if (ssh_x509store_lookup(
	      x509revoked, X509_LU_CRL,
	      X509_get_issuer_name(cert),
	      &xobj) > 0) {
		ok = !ssh_is_cert_revoked(ctx, xobj.data.crl, cert);
	}
	X509_OBJECT_free_contents(&xobj);
	/* clear rest of errors in OpenSSL "error buffer" */
	ERR_clear_error();

	if (!ok) return(0);

	/**/
	return(ok);
}
#endif

#endif /*ndef SSH_X509STORE_DISABLED*/
