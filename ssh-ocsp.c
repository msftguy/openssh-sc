/*
 * Copyright (c) 2004-2007,2011 Roumen Petrov.  All rights reserved.
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
#ifndef SSH_OCSP_ENABLED
#  include "error: OCSP is disabled"
#endif

#if 1
#  /* not yet fully implemented */
#  define SSH_WITH_SSLOCSP
#endif

#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#ifdef SSH_WITH_SSLOCSP
#  include <openssl/ssl.h>
#endif

#ifdef sk_OPENSSL_STRING_new_null
/*
 * STACK_OF(OPENSSL_STRING) is defined for openssl version >= 1.0
 * (OPENSSL_VERSION_NUMBER >= 0x10000000L).
 * NOTE: We will test for definition of sk_OPENSSL_STRING_new_null
 * instead openssl version number !
 */
#define ssh_sk_OPENSSL_STRING		STACK_OF(OPENSSL_STRING)

static void OPENSSL_STRING_xfree(OPENSSL_STRING p) {
/* xfree warnings for OpenSSL 1+:
.../ssh-ocsp.c: In function 'ssh_ocsp_validate2':
.../ssh-ocsp.c:845: warning: pointer type mismatch in conditional expression
.../ssh-ocsp.c:845: warning: ISO C forbids conversion of object pointer to function pointer type
*/
  xfree(p);
}

#else /* !def sk_OPENSSL_STRING_new_null */

#ifdef sk_STRING_new_null
/*some OpenSSL 1.0 pre and release candidate */
# define ssh_sk_OPENSSL_STRING		STACK_OF(STRING)
# define sk_OPENSSL_STRING_new_null	sk_STRING_new_null
# define sk_OPENSSL_STRING_push		sk_STRING_push
# define sk_OPENSSL_STRING_num		sk_STRING_num
# define sk_OPENSSL_STRING_value	sk_STRING_value
# define sk_OPENSSL_STRING_pop_free	sk_STRING_pop_free

static void OPENSSL_STRING_xfree(STRING p) {
  xfree(p);
}

#else /* !def sk_STRING_new_null */

# define ssh_sk_OPENSSL_STRING		STACK
# define sk_OPENSSL_STRING_new_null	sk_new_null
# define sk_OPENSSL_STRING_push		sk_push
# define sk_OPENSSL_STRING_num		sk_num
# define sk_OPENSSL_STRING_value	sk_value
# define sk_OPENSSL_STRING_pop_free	sk_pop_free

#define OPENSSL_STRING_xfree		xfree

#endif

#endif

static VAOptions va = { SSHVA_NONE, NULL, NULL };

typedef struct va_type_map_s va_type_map;
struct va_type_map_s {
	int id;
	const char* code;
};

static va_type_map sshva_type_map[] = {
	{ SSHVA_NONE     , "none"     },
	{ SSHVA_OCSP_CERT, "ocspcert" },
	{ SSHVA_OCSP_SPEC, "ocspspec" },
};


int
ssh_get_default_vatype(void) {
	return(SSHVA_NONE);
}


int
ssh_get_vatype_s(const char* type) {
	int k, n;

	if (type == NULL) return(-1);

	n = sizeof(sshva_type_map) / sizeof(sshva_type_map[0]);
	for (k = 0; k < n; k++) {
		va_type_map *p = sshva_type_map + k;
		if (strcasecmp(type, p->code) == 0) return(p->id);
	}

	return(-1);
}


static void
ssh_set_vatype(int type) {
	switch (type) {
	case SSHVA_NONE:
	case SSHVA_OCSP_CERT:
	case SSHVA_OCSP_SPEC:
		va.type = type;
		break;
	default:
		fatal("ssh_set_vatype: invalid type %d", type);
		break;
	}
}


void
ssh_set_validator(const VAOptions *_va) {
	if (va.certificate_file != NULL) {
		xfree((void*)va.certificate_file);
		va.certificate_file = NULL;
	}
	if (va.responder_url != NULL) {
		xfree((void*)va.responder_url);
		va.responder_url = NULL;
	}
	if (_va == NULL) {
		debug("ssh_set_validator: NULL options - set vatype to none");
		ssh_set_vatype(SSHVA_NONE);
		return;
	}

	ssh_set_vatype(_va->type); /*fatal on error*/
	if (_va->certificate_file != NULL) {
		switch(va.type) {
		case SSHVA_NONE:
		case SSHVA_OCSP_CERT:
			debug("ssh_set_validator: ignore certificate file");
			break;
		case SSHVA_OCSP_SPEC:
			va.certificate_file = xstrdup(_va->certificate_file); /*fatal on error*/
			break;
		}
	}
	switch(va.type) {
	case SSHVA_NONE:
	case SSHVA_OCSP_CERT:
		debug("ssh_set_validator: ignore responder url");
		break;
	case SSHVA_OCSP_SPEC:
		if (_va->responder_url == NULL) {
			fatal("ssh_set_validator: responder url is mandatory");
		}
		va.responder_url = xstrdup(_va->responder_url); /*fatal on error*/
		break;
	}
}


static void
openssl_error(const char *ssh_method, const char *openssl_method) {
	char buf[512];

	openssl_errormsg(buf, sizeof(buf));
	error("%.128s: %.128s fail with errormsg='%.*s'"
		, ssh_method
		, openssl_method
		, (int) sizeof(buf), buf);
}


static char*
ssh_ASN1_GENERALIZEDTIME_2_string(ASN1_GENERALIZEDTIME *asn1_time) {
	BIO    *bio;
	int     k;
	char   *p = NULL;

	if (asn1_time == NULL) {
		error("ssh_ASN1_GENERALIZEDTIME_2_string: asn1_time is NULL");
		return(NULL);
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		error("ssh_ASN1_GENERALIZEDTIME_2_string: BIO_new fail");
		return(NULL);
	}

	ASN1_GENERALIZEDTIME_print(bio, asn1_time);
	BIO_flush(bio);

	k = BIO_pending(bio);
	p = xmalloc(k + 1); /*fatal on error*/
	k = BIO_read(bio, p, k);
	p[k] = '\0';
	BIO_free_all(bio);
	return(p);
}


static STACK_OF(X509)*
ssh_load_x509certs(const char *certs_file, const char* certs_descrip) {
	STACK_OF(X509) *ret_certs = NULL;
	BIO *fbio = NULL;

	if (certs_file == NULL) {
		error("ssh_load_x509certs: file is NULL");
		goto exit;
	}

	ret_certs = sk_X509_new_null();
	if (ret_certs == NULL) {
		error("ssh_load_x509certs: sk_X509_new_null fail");
		goto exit;
	}

	fbio = BIO_new(BIO_s_file());
	if (fbio == NULL) {
		error("ssh_load_x509certs: BIO_new fail");
		goto exit;
	}

	if (BIO_read_filename(fbio, certs_file) <= 0) {
		openssl_error("ssh_load_x509certs", "BIO_read_filename");
		logit("ssh_load_x509certs:"
			" description/filename='%.512s'/'%.512s'"
			, certs_descrip
			, certs_file);
		goto exit;
	}

	{
		int k;
		STACK_OF(X509_INFO) *data;

		data = PEM_X509_INFO_read_bio(fbio, NULL, NULL, NULL);
		if (data == NULL) {
			error("ssh_load_x509certs: no data.");
			goto exit;
		}

		for (k = 0; k < sk_X509_INFO_num(data); k++) {
			X509_INFO *xi = sk_X509_INFO_value(data, k);
			if (xi->x509) {
				sk_X509_push(ret_certs, xi->x509);
				xi->x509 = NULL;
			}
		}
		sk_X509_INFO_pop_free(data, X509_INFO_free);
	}

exit:
	if (fbio != NULL) BIO_free_all(fbio);
	if (ret_certs != NULL) {
		debug3("ssh_load_x509certs: return %d certs", (int)sk_X509_num(ret_certs));
	} else {
		debug("ssh_load_x509certs: return NULL");
	}
	return(ret_certs);
}


static int/*bool*/
ssh_ocspreq_addcert(
	X509 *cert,
	X509_STORE* x509store,
	OCSP_REQUEST *req,
	STACK_OF(OCSP_CERTID) *ids,
	ssh_sk_OPENSSL_STRING *subjs
) {
	X509        *issuer = NULL;
	OCSP_CERTID *id = NULL;
	char        *subj = NULL;

	if (cert == NULL) {
		error("ssh_ocspreq_addcert: cert is NULL");
		return(0);
	}
	if (x509store == NULL) {
		error("ssh_ocspreq_addcert: x509store is NULL");
		return(0);
	}
	if (req == NULL) {
		error("ssh_ocspreq_addcert: req is NULL");
		return(0);
	}
	if (ids == NULL) {
		error("ssh_ocspreq_addcert: ids is NULL");
		return(0);
	}
	if (subjs == NULL) {
		error("ssh_ocspreq_addcert: subjs is NULL");
		return(0);
	}

	{
		X509_OBJECT xobj;
		memset(&xobj, 0, sizeof(xobj));
		if (ssh_x509store_lookup(x509store, X509_LU_X509, X509_get_issuer_name(cert), &xobj) > 0) {
			issuer = xobj.data.x509;
		}
		X509_OBJECT_free_contents(&xobj);
	}
	if (issuer == NULL) {
		error("ssh_ocspreq_addcert: cannot found issuer certificate");
		return(0);
	}

	id = OCSP_cert_to_id(NULL, cert, issuer);
	if (id == NULL) {
		error("ssh_ocspreq_addcert: OCSP_cert_to_id fail");
		return(0);
	}

	if (!OCSP_request_add0_id(req, id)) {
		error("ssh_ocspreq_addcert: OCSP_request_add0_id fail");
		return(0);
	}
	if (!sk_OCSP_CERTID_push(ids, id)) {
		error("ssh_ocspreq_addcert: sk_OCSP_CERTID_push fail");
		return(0);
	}
	subj = ssh_X509_NAME_oneline(X509_get_subject_name(cert)); /*fatal on error*/
	if (!sk_OPENSSL_STRING_push(subjs, subj)) {
		error("ssh_ocspreq_addcert: sk_push(..., subj) fail");
		return(0);
	}

	return(1);
}


struct ssh_ocsp_conn_s {
	const char     *url;

#ifdef SSH_WITH_SSLOCSP
	int             use_ssl;
#endif
	/*pointers inside data buffer*/
	/*const*/ char *host;
	const char     *port;
	const char     *path;

	/*data buffer to hold all connection info*/
	char           *data;
};

typedef struct ssh_ocsp_conn_s ssh_ocsp_conn;


static void
ssh_ocsp_conn_free(ssh_ocsp_conn **pconn) {
	ssh_ocsp_conn *conn = *pconn;

	if (conn == NULL) return;
	*pconn = NULL;

	/* we don't need to clean items */
	if (conn->path != NULL) xfree((void*)conn->path);
	if (conn->data != NULL) xfree(conn->data);
	if (conn->url  != NULL) xfree((void*)conn->url );
	xfree(conn);
}


static int/*bool*/
ssh_ocsp_set_protocol(ssh_ocsp_conn *conn, const char *protocol) {
	if (strcmp(protocol, "http") == 0) {
#ifdef SSH_WITH_SSLOCSP
		conn->use_ssl = 0;
#endif
		return(1);
	}

#ifdef SSH_WITH_SSLOCSP
	if (strcmp(protocol, "https") == 0) {
		conn->use_ssl = 1;
		return(1);
	}
#endif

#ifdef SSH_WITH_SSLOCSP
	conn->use_ssl = -1;
#endif
	return(0);
}


static ssh_ocsp_conn*
ssh_ocsp_conn_new(const char *url) {
	ssh_ocsp_conn *conn = NULL;
	char *p = NULL;
	char *q = NULL;

	if (url == NULL) {
		error("ssh_ocsp_conn_new: url is NULL");
		return(NULL);
	}

	conn = xmalloc(sizeof(*conn)); /*fatal on error*/
	memset(conn, 0, sizeof(*conn));

	conn->url = xstrdup(url); /*fatal on error*/
	conn->data = xstrdup(url); /*fatal on error*/

	/* chech for protocol */
	p = conn->data;
	q = strchr(p, ':');
	if (q == NULL) goto error;
	*q = '\x0';

	if (!ssh_ocsp_set_protocol(conn, p)) {
		error("ssh_ocsp_conn_new:"
			" unsupported protocol '%.16s'"
			, p);
		goto error;
	}

	p = q;
	if (*++p != '/') { /*this symbol is inside data */
		error("ssh_ocsp_conn_new: expected first slash,"
			" got char with code %d"
			, (int)*p);
		goto error;
	}
	if (*++p != '/') { /*this symbol is inside data */
		error("ssh_ocsp_conn_new: expected second slash,"
			" got char with code %d"
			, (int)*p);
		goto error;
	}

	/* chech for host and port */
	if (*++p == '\x0') {
		error("ssh_ocsp_conn_new: missing host in url '%.512s'", url);
		goto error;
	}
	conn->host = p;
	q = strchr(p, '/');
	if (q != NULL) {
		if (q[1] != '\x0') conn->path = xstrdup(q); /*fatal on error*/
		*q = '\x0';
		/* now p(conn->host) point only to host{:port} */
	}
	/*else q is NULL !!!*/

	/* chech for port */
	p = strrchr(conn->host, ':');
	if (p != NULL) {
		*p = '\x0';
		if (*++p != '\x0') conn->port = p;
	}
	if (conn->port == NULL) {
#ifdef SSH_WITH_SSLOCSP
		conn->port = conn->use_ssl ? "443" : "80";
#else
		conn->port = "80";
#endif
	}

exit:
	return(conn);
error:
	ssh_ocsp_conn_free(&conn);
	goto exit;
}


static OCSP_RESPONSE*
ssh_ocsp_get_response(const ssh_ocsp_conn *conn, OCSP_REQUEST *req) {
	OCSP_RESPONSE *resp = NULL;
	BIO           *bio_conn = NULL;
#ifdef SSH_WITH_SSLOCSP
	SSL_CTX       *ctx = NULL;
#endif

	if (conn == NULL) {
		error("ssh_ocsp_get_response: conn is NULL");
		return(NULL);
	}
	if (req == NULL) {
		error("ssh_ocsp_get_response: req is NULL");
		return(NULL);
	}

#ifndef OPENSSL_NO_SOCK
	bio_conn = BIO_new_connect(conn->host);
	if (bio_conn == NULL) {
		openssl_error("ssh_ocsp_get_response", "BIO_new_connect");
		goto exit;
	}
#else
	error("ssh_ocsp_get_response: sockets are not supported in OpenSSL");
	goto exit;
#endif
	if (conn->port != NULL) {
		BIO_set_conn_port(bio_conn, conn->port);
	}

#ifdef SSH_WITH_SSLOCSP
	if (conn->use_ssl == 1) {
		BIO *bio_sslconn;
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
		ctx = SSL_CTX_new(SSLv23_client_method());
#elif !defined(OPENSSL_NO_SSL3)
		ctx = SSL_CTX_new(SSLv3_client_method());
#elif !defined(OPENSSL_NO_SSL2)
		ctx = SSL_CTX_new(SSLv2_client_method());
#else
		error("ssh_ocsp_get_response: SSL is disabled");
		goto exit;
#endif
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		bio_sslconn = BIO_new_ssl(ctx, 1);
		bio_conn = BIO_push(bio_sslconn, bio_conn);
	}
#endif /*def SSH_WITH_SSLOCSP*/

	if (BIO_do_connect(bio_conn) <= 0) {
		openssl_error("ssh_ocsp_get_response", "BIO_do_connect");
		goto exit;
	}

	/*
	 * OCSP_sendreq_bio accept null as path argument but if path
	 * is null http request will contain <NULL> what is incorrect.
	 */
	resp = OCSP_sendreq_bio(bio_conn, (char*)(conn->path ? conn->path : "/") , req);
	if (resp == NULL) {
		openssl_error("ssh_ocsp_get_response", "OCSP_sendreq_bio");
	}

exit:
	if (bio_conn != NULL) BIO_free_all(bio_conn);
#ifdef SSH_WITH_SSLOCSP
	if (ctx      != NULL) SSL_CTX_free(ctx);
#endif

	return(resp);
}


static OCSP_BASICRESP*
ssh_ocsp_get_basicresp(
	OCSP_REQUEST	*req,
	OCSP_RESPONSE	*resp,
	STACK_OF(X509)	*vacrts,
	X509_STORE	*x509store
) {
	OCSP_BASICRESP *br = NULL;
	unsigned long basic_verify_flags = 0/*NO:OCSP_NOEXPLICIT*/;
	int	flag;

	if (req == NULL) {
		error("ssh_ocsp_get_basicresp: req is NULL");
		return(NULL);
	}
	if (resp == NULL) {
		error("ssh_ocsp_get_basicresp: resp is NULL");
		return(NULL);
	}
	if (x509store == NULL) {
		error("ssh_ocsp_get_basicresp: x509store is NULL");
		return(NULL);
	}

	br = OCSP_response_get1_basic(resp);
	if (br == NULL) {
		openssl_error("ssh_ocsp_get_basicresp", "OCSP_response_get1_basic");
		return(NULL);
	}

	flag = OCSP_check_nonce(req, br);
	if (flag <= 0) {
		if (flag == -1) {
			logit("ssh_ocsp_get_basicresp: WARNING - no nonce in response");
		} else {
			openssl_error("ssh_ocsp_get_basicresp", "OCSP_check_nonce");
			goto error;
		}
	}

#ifdef SSHOCSPTEST
{
int k;
logit("ssh_ocsp_get_basicresp: VA certs num=%d", sk_X509_num(vacrts));
for (k = 0; k < sk_X509_num(vacrts); k++) {
	char *buf;
	X509 *x = sk_X509_value(vacrts, k);
	buf = ssh_X509_NAME_oneline(X509_get_subject_name(x)); /*fatal on error*/
	logit("ssh_ocsp_get_basicresp: VA[%d] subject='%s'", k, buf);
	xfree(buf);
}
}
#endif /*def SSHOCSPTEST*/

/*
 * RFC2560:
 * ...
 * All definitive response messages SHALL be digitally signed. The key
 * used to sign the response MUST belong to one of the following:
 *
 * -- the CA who issued the certificate in question
 * -- a Trusted Responder whose public key is trusted by the requester
 * -- a CA Designated Responder (Authorized Responder) who holds a
 *    specially marked certificate issued directly by the CA, indicating
 *    that the responder may issue OCSP responses for that CA
 * ...
 *
 * TODO: to check OpenSLL implementation
 */
	if ((vacrts == NULL) || (sk_X509_num(vacrts) <= 0)) {
		flag = -1;
	} else {
		/*
		 * With flag OCSP_TRUSTOTHER:
		 * - we never get error 'without missing ocspsigning
		 *   usage' for VA certificate !!!
		 * Without flag OCSP_TRUSTOTHER:
		 * - we can get OCSP_basic_verify error "root ca not trusted"
		 */
#if 0
		flag = OCSP_basic_verify(br, vacrts, x509store, basic_verify_flags | OCSP_TRUSTOTHER);
#else
		flag = OCSP_basic_verify(br, vacrts, x509store, basic_verify_flags);
#endif
	}
	if (flag < 0) {
		flag = OCSP_basic_verify(br, NULL, x509store, basic_verify_flags);
	}
	if (flag <= 0) {
		openssl_error("ssh_ocsp_get_basicresp", "OCSP_basic_verify");
		logit("ssh_ocsp_get_basicresp: flag=%d", flag);
		goto error;
	}

	debug3("ssh_ocsp_get_basicresp: OK");
	return(br);

error:
	debug3("ssh_ocsp_get_basicresp: FAIL");
	if (br != NULL) OCSP_BASICRESP_free(br);
	return(NULL);
}


/*
 * Method return value:
 *  1 - all cert.-s are good
 * -1 - error or at least one cert. with status unknow
 *  0 - otherwise, i.e. at least one cert. is revoked and rest are good
 */
static int
ssh_ocsp_check_validity(
	OCSP_REQUEST *req,
	OCSP_BASICRESP *br,
	STACK_OF(OCSP_CERTID) *ids,
	ssh_sk_OPENSSL_STRING *subjs
) {
	int ret = 1;
	/* Maximum leeway in validity period: default 5 minutes */
	const long nsec = (5 * 60);
	const long maxage = -1;

	int k;
	int status, reason;
	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

	if (req == NULL) {
		error("ssh_ocsp_check_validity: req is NULL");
		return(-1);
	}
	if (br == NULL) {
		error("ssh_ocsp_check_validity: br is NULL");
		return(-1);
	}
	if (sk_OCSP_CERTID_num(ids) <= 0) {
		error("ssh_ocsp_check_validity:"
			" number of ids is %d"
			, sk_OCSP_CERTID_num(ids));
		return(-1);
	}
	if (sk_OPENSSL_STRING_num(subjs) <= 0) {
		error("ssh_ocsp_check_validity:"
			" number of subjs is %d"
			, sk_OPENSSL_STRING_num(subjs));
		return(-1);
	}
	if (sk_OCSP_CERTID_num(ids) != sk_OPENSSL_STRING_num(subjs)) {
		error("ssh_ocsp_check_validity:"
			" ids(%d) != subjs(%d)"
			, sk_OCSP_CERTID_num(ids)
			, sk_OPENSSL_STRING_num(subjs));
		return(-1);
	}

	for (k = 0; k < sk_OCSP_CERTID_num(ids); k++) {
		OCSP_CERTID *id = sk_OCSP_CERTID_value(ids, k);

		if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
			char *subject = sk_OPENSSL_STRING_value(subjs, k);
			debug3("ssh_ocsp_check_validity: cert[%d]='%s'", k, subject);
		}

		if (!OCSP_resp_find_status(
			br, id, &status, &reason,
			&rev, &thisupd, &nextupd)
		) {
			ret = -1;
			error("ssh_ocsp_check_validity: cannot found status");
			break;
		}

		if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
			char ebuf[512];
			ret = -1;
			logit("ssh_ocsp_check_validity: "
				" WARNING-invalid status time."
				" OCSP_check_validity fail with errormsg='%.512s'"
				, openssl_errormsg(ebuf, sizeof(ebuf)));
			break;
		}
		debug("ssh_ocsp_check_validity: status=%.32s", OCSP_cert_status_str(status));
		if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
			char *p = ssh_ASN1_GENERALIZEDTIME_2_string(thisupd);
			debug3("ssh_ocsp_check_validity: This Update=%.128s", p);
			xfree(p);
			if (nextupd != NULL) {
				p = ssh_ASN1_GENERALIZEDTIME_2_string(nextupd);
				debug3("ssh_ocsp_check_validity: Next Update=%.128s", p);
				xfree(p);
			}
		}

		if (status == V_OCSP_CERTSTATUS_GOOD) continue;

		if (status != V_OCSP_CERTSTATUS_REVOKED) {
			ret = -1;
			error("ssh_ocsp_check_validity: unknow certificate status");
			break;
		}

		ret = 0;
		if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
			char *p = ssh_ASN1_GENERALIZEDTIME_2_string(rev);
			debug3("ssh_ocsp_check_validity: Revocation Time=%.128s", p);
			xfree(p);
			if (reason != -1) {
				debug3("ssh_ocsp_check_validity:"
					" Revocation Reason='%.128s'"
					, OCSP_crl_reason_str(reason));
			}
		}
		break;
	}
	debug3("ssh_ocsp_check_validity: return %d", ret);
	return(ret);
}


static int
ssh_ocsp_validate2(
	X509 *cert,
	X509_STORE *x509store,
	const ssh_ocsp_conn *ocsp
) {
	int ret = -1;
	int add_nonce = 0;

	STACK_OF(X509)        *vacrts = NULL;
	OCSP_REQUEST          *req = OCSP_REQUEST_new();
	STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
	ssh_sk_OPENSSL_STRING *subjs = sk_OPENSSL_STRING_new_null();
	OCSP_RESPONSE         *resp = NULL;
	OCSP_BASICRESP        *br = NULL;

	if ((va.type == SSHVA_OCSP_SPEC) &&
	    (va.certificate_file != NULL)) {
		vacrts = ssh_load_x509certs(va.certificate_file, "'OCSP Responder' trusted certificates");
		if (vacrts == NULL) goto exit;
		debug("ssh_ocsp_validate2: VA certs num=%d", sk_X509_num(vacrts));
	}

	if (!ssh_ocspreq_addcert(cert, x509store, req, ids, subjs)) {
		goto exit;
	}

	if (req && add_nonce) {
		OCSP_request_add1_nonce(req, NULL, -1);
	}

	resp = ssh_ocsp_get_response(ocsp, req);
	if (resp == NULL) goto exit;

	{ /*check OCSP response status*/
		int flag = OCSP_response_status(resp);
		if (flag != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
			error("ssh_ocsp_validate2:"
				" responder error=%d(%.256s)"
				, flag
				, OCSP_response_status_str((long/*???*/)flag));
			goto exit;
		}
	}

	br = ssh_ocsp_get_basicresp(req, resp, vacrts, x509store);
	if (br == NULL) goto exit;

	ret = ssh_ocsp_check_validity(req, br, ids, subjs);

exit:
	if (br     != NULL)	OCSP_BASICRESP_free(br);
	if (resp   != NULL)	OCSP_RESPONSE_free(resp);
	if (subjs  != NULL)	sk_OPENSSL_STRING_pop_free(subjs, OPENSSL_STRING_xfree);
	if (ids    != NULL)	sk_OCSP_CERTID_free(ids);
	if (req    != NULL)	OCSP_REQUEST_free(req);
	if (vacrts != NULL)	sk_X509_pop_free(vacrts, X509_free);

	return(ret);
}


static AUTHORITY_INFO_ACCESS*
ssh_aia_get(X509_EXTENSION *ext) {
	X509V3_EXT_METHOD *method = NULL;
	void *ext_str = NULL;
	const unsigned char *p;
	int len;

	if (ext == NULL) {
		error("ssh_aia_get: ext is NULL");
		return(NULL);
	}

	method = (X509V3_EXT_METHOD*) X509V3_EXT_get(ext);
	if (method == NULL) {
		debug("ssh_aia_get: cannot get method");
		return(NULL);
	}

	p = ext->value->data;
	len = ext->value->length;
	if (method->it) {
		ext_str = ASN1_item_d2i(NULL, &p, len, ASN1_ITEM_ptr(method->it));
	} else {
		ext_str = method->d2i(NULL, &p, len);
	}
	if (ext_str == NULL) {
		debug("ssh_aia_get: null ext_str!");
		return(NULL);
	}

	return((AUTHORITY_INFO_ACCESS*)ext_str);
}


static void
ssh_aia_free(X509_EXTENSION *ext, AUTHORITY_INFO_ACCESS* aia) {
	X509V3_EXT_METHOD *method = NULL;

	if (ext == NULL) {
		error("ssh_aia_free: ext is NULL");
		return;
	}

	method = (X509V3_EXT_METHOD*) X509V3_EXT_get(ext);
	if (method == NULL) return;

	if (method->it) {
		ASN1_item_free((void*)aia, ASN1_ITEM_ptr(method->it));
	} else {
		method->ext_free(aia);
	}
}


static int
ssh_aiaocsp_validate(
	X509 *cert,
	X509_STORE *x509store,
	AUTHORITY_INFO_ACCESS *aia,
	int *has_ocsp_url
) {
	int ret = -1;
	int k;
	if (has_ocsp_url == NULL) {
		fatal("ssh_aiaocsp_validate: has_ocsp_url is NULL");
		return(-1); /*;-)*/
	}

	*has_ocsp_url = 0;
	for (k = 0; k < sk_ACCESS_DESCRIPTION_num(aia); k++) {
		ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, k);
		GENERAL_NAME *gn;
		ASN1_IA5STRING *uri;
		ssh_ocsp_conn *conn;

		if (OBJ_obj2nid(ad->method) != NID_ad_OCSP) continue;

		gn = ad->location;
#if 0
{
BIO *bio = BIO_new_fp(stderr, BIO_NOCLOSE);
if (bio != NULL) {
	BIO_puts(bio, "gn->type:");
	switch (gn->type) {
	case GEN_OTHERNAME : BIO_puts(bio, "GEN_OTHERNAME"); break;
	case GEN_EMAIL     : BIO_puts(bio, "GEN_EMAIL"    ); break;
	case GEN_DNS       : BIO_puts(bio, "GEN_DNS"      ); break;
	case GEN_X400      : BIO_puts(bio, "GEN_X400"     ); break;
	case GEN_DIRNAME   : BIO_puts(bio, "GEN_DIRNAME"  ); break;
	case GEN_EDIPARTY  : BIO_puts(bio, "GEN_EDIPARTY" ); break;
	case GEN_URI       : BIO_puts(bio, "GEN_URI"      ); break;
	case GEN_IPADD     : BIO_puts(bio, "GEN_IPADD"    ); break;
	case GEN_RID       : BIO_puts(bio, "GEN_RID"      ); break;
	default            : BIO_puts(bio, "[unsupported]"); break;
	}
	BIO_puts(bio, "\n");
	BIO_free(bio);
}
}
#endif
		if (gn->type != GEN_URI) continue;

		uri = gn->d.uniformResourceIdentifier;
		*has_ocsp_url = 1;

		conn = ssh_ocsp_conn_new((const char*)uri->data);
		if (conn == NULL) {
			debug("ssh_aiaocsp_validate: cannot create ocsp connection");
			continue;
		}
		ret = ssh_ocsp_validate2(cert, x509store, conn);
		ssh_ocsp_conn_free(&conn);

		if (ret >= 0) break;
	}

	return(*has_ocsp_url ? ret : 1);
}


static int
ssh_ocsp_validate4cert(X509 *cert, X509_STORE *x509store) {
	int found = 0;
	int ret = -1;
	int loc = -1;

	if (cert == NULL) return(0);

	for (	loc = X509_get_ext_by_NID(cert, NID_info_access, loc);
		loc >= 0;
		loc = X509_get_ext_by_NID(cert, NID_info_access, loc)
	) {
		X509_EXTENSION	*xe;

		xe = X509_get_ext(cert, loc);
		if (xe == NULL) {
			debug("ssh_ocsp_validate4cert: cannot get x509 extension");
			continue;
		}

		{/*validate from AIA*/
			AUTHORITY_INFO_ACCESS	*aia = ssh_aia_get(xe);
			if (aia == NULL) continue;

			ret = ssh_aiaocsp_validate(cert, x509store, aia, &found);

			ssh_aia_free(xe, aia);
		}

		if (ret >= 0) break;
	}

	if (found) {
		debug3("ssh_ocsp_validate4cert: validation result=%d", ret);
	} else {
		debug3("ssh_ocsp_validate4cert: no OCSP 'Service Locator' URL");
	}
	return(found ? ret : 1);
}


int
ssh_ocsp_validate(X509 *cert, X509_STORE *x509store) {
	int ret = -1;
	ssh_ocsp_conn	*conn = NULL;

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf = ssh_X509_NAME_oneline(X509_get_subject_name(cert)); /*fatal on error*/
		debug3("ssh_ocsp_validate: for '%s'", buf);
		xfree(buf);
	}

	switch (va.type) {
	default:
		/*when something is missing*/
		fatal("ssh_ocsp_validate: invalid validator type %d", va.type);
		break; /*;-)*/
	case SSHVA_NONE:
		debug3("ssh_ocsp_validate: none");
		ret = 1;
		break;
	case SSHVA_OCSP_CERT:
		ret = ssh_ocsp_validate4cert(cert, x509store);
		break;
	case SSHVA_OCSP_SPEC:
		conn = ssh_ocsp_conn_new(va.responder_url);
		if (conn != NULL) {
			ret = ssh_ocsp_validate2(cert, x509store, conn);
			ssh_ocsp_conn_free(&conn);
		}
		break;
	}

	return(ret);
}
