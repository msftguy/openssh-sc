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

#include "x509_by_ldap.h"
/* Prefered X509_NAME_cmp method from ssh-x509.c */
extern int     ssh_X509_NAME_cmp(X509_NAME *a, X509_NAME *b);
#include <string.h>
#ifndef LDAP_DEPRECATED
   /* to suppress warnings in some 2.3x versions */
#  define LDAP_DEPRECATED 0
#endif
#include <ldap.h>


/* ================================================================== */
/* ERRORS */
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA X509byLDAP_str_functs[] = {
	{ ERR_PACK(0, X509byLDAP_F_LOOKUPCRTL, 0)	, "LOOKUPCRTL" },
	{ ERR_PACK(0, X509byLDAP_F_LDAPHOST_NEW, 0)	, "LDAPHOST_NEW" },
	{ ERR_PACK(0, X509byLDAP_F_SET_PROTOCOL, 0)	, "SET_PROTOCOL" },
	{ ERR_PACK(0, X509byLDAP_F_RESULT2STORE, 0)	, "RESULT2STORE" },
	{ ERR_PACK(0, X509byLDAP_F_GET_BY_SUBJECT, 0)	, "GET_BY_SUBJECT" },
	{ 0, NULL }
};


static ERR_STRING_DATA X509byLDAP_str_reasons[] = {
	{ X509byLDAP_R_INVALID_CRTLCMD			, "invalid control command" },
	{ X509byLDAP_R_NOT_LDAP_URL			, "not ldap url" },
	{ X509byLDAP_R_INVALID_URL			, "invalid ldap url" },
	{ X509byLDAP_R_INITIALIZATION_ERROR		, "ldap initialization error" },
	{ X509byLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION	, "unable to get ldap protocol version" },
	{ X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION	, "unable to set ldap protocol version" },
	{ X509byLDAP_R_UNABLE_TO_COUNT_ENTRIES		, "unable to count ldap entries" },
	{ X509byLDAP_R_WRONG_LOOKUP_TYPE		, "wrong lookup type" },
	{ X509byLDAP_R_UNABLE_TO_GET_FILTER		, "unable to get ldap filter" },
	{ X509byLDAP_R_UNABLE_TO_BIND			, "unable to bind to ldap server" },
	{ X509byLDAP_R_SEARCH_FAIL			, "search failure" },
	{ 0, NULL }
};
#endif /*ndef OPENSSL_NO_ERR*/


void
ERR_load_X509byLDAP_strings(void) {
	static int init = 1;

	if (init) {
		init = 0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(ERR_LIB_X509byLDAP, X509byLDAP_str_functs);
		ERR_load_strings(ERR_LIB_X509byLDAP, X509byLDAP_str_reasons);
#endif
	}
}


static char*
ldap_errormsg(char *buf, size_t len, int err) {
	snprintf(buf, len, "ldaperror=0x%x(%.256s)", err, ldap_err2string(err));
	return(buf);
}


static void
openssl_add_ldap_error(int err) {
	char	buf[512];
	ERR_add_error_data(1, ldap_errormsg(buf, sizeof(buf), err));
}


/* ================================================================== */
/* wrappers to some depricated functions */
static void
ldaplookup_parse_result (
	LDAP *ld,
	LDAPMessage *res
) {
	static const int freeit = 0;
	int result;
#ifdef HAVE_LDAP_PARSE_RESULT
	int ret;
	char *matcheddn;
	char *errmsg;

	ret = ldap_parse_result(ld, res, &result, &matcheddn, &errmsg, NULL, NULL, freeit);
	if (ret == LDAP_SUCCESS) {
		if (errmsg) ERR_add_error_data(1, errmsg);
	}
	if (matcheddn) ldap_memfree(matcheddn);
	if (errmsg)    ldap_memfree(errmsg);
#else
	result = ldap_result2error(ld, res, freeit);
	openssl_add_ldap_error(result);
#endif
}


static int
ldaplookup_bind_s(LDAP *ld) {
	int result;

	/* anonymous bind - data must be retrieved by anybody */
#ifdef HAVE_LDAP_SASL_BIND_S
{
	static struct berval	cred = { 0, (char*)"" };

	result = ldap_sasl_bind_s(
		ld, NULL/*dn*/, LDAP_SASL_SIMPLE, &cred,
		NULL, NULL, NULL);
}
#else
	result = ldap_simple_bind_s(ld, NULL/*binddn*/, NULL/*bindpw*/);
#endif

#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_bind_s:"
" ldap_XXX_bind_s return 0x%x(%s)\n"
, result, ldap_err2string(result));
#endif
	return(result);
}


static int
ldaplookup_search_s(
	LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPMessage **res
) {
	int result;
#ifdef HAVE_LDAP_SEARCH_EXT_S
	result = ldap_search_ext_s(ld, base,
		scope, filter, attrs, attrsonly,
		NULL, NULL, NULL, 0, res);
#else
	result = ldap_search_s(ld, base, scope, filter, attrs, attrsonly, res);
#endif

#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_search_s:"
"\n base=%s\n filter=%s\n"
" ldap_search_{XXX}s return 0x%x(%s)\n"
, base, filter
, result, ldap_err2string(result));
#endif
	return(result);
}


/* ================================================================== */
/* LOOKUP by LDAP */

static const char ATTR_CACERT[] = "cACertificate";
static const char ATTR_CACRL[] = "certificateRevocationList";

typedef struct ldaphost_s ldaphost;
struct ldaphost_s {
	char        *url;
	char        *binddn;
	char        *bindpw;
	LDAPURLDesc *ldapurl;
	LDAP        *ld;
	ldaphost    *next;
};


static ldaphost* ldaphost_new(const char *url);
static void ldaphost_free(ldaphost *p);


static int  ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret);
static int  ldaplookup_new(X509_LOOKUP *ctx);
static void ldaplookup_free(X509_LOOKUP *ctx);
static int  ldaplookup_init(X509_LOOKUP *ctx);
static int  ldaplookup_shutdown(X509_LOOKUP *ctx);
static int  ldaplookup_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret);

static int  ldaplookup_add_search(X509_LOOKUP *ctx, const char *url);
static int  ldaplookup_set_protocol(X509_LOOKUP *ctx, const char *ver);


X509_LOOKUP_METHOD x509_ldap_lookup = {
	"Load certs and crls from LDAP server",
	ldaplookup_new,		/* new */
	ldaplookup_free,	/* free */
	ldaplookup_init,	/* init */
	ldaplookup_shutdown,	/* shutdown */
	ldaplookup_ctrl,	/* ctrl */
	ldaplookup_by_subject,	/* get_by_subject */
	NULL,			/* get_by_issuer_serial */
	NULL,			/* get_by_fingerprint */
	NULL,			/* get_by_alias */
};


X509_LOOKUP_METHOD*
X509_LOOKUP_ldap(void) {
	return(&x509_ldap_lookup);
}


static int
ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **retp) {
	int ret = 0;

	(void)argl;
	(void)retp;
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_ctrl: cmd=%d, argc=%s\n", cmd, argc);
#endif
	switch (cmd) {
	case X509_L_LDAP_HOST:
		ret = ldaplookup_add_search(ctx, argc);
		break;
	case X509_L_LDAP_VERSION:
		ret = ldaplookup_set_protocol(ctx, argc);
		break;
	default:
		X509byLDAPerr(X509byLDAP_F_LOOKUPCRTL, X509byLDAP_R_INVALID_CRTLCMD);
		break;
	}
	return(ret);
}


static int
ldaplookup_new(X509_LOOKUP *ctx) {
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_new:\n");
#endif
	if (ctx == NULL)
		return(0);

	ctx->method_data = NULL;
	return(1);
}


static void
ldaplookup_free(X509_LOOKUP *ctx) {
	ldaphost *p;
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_free:\n");
#endif

	if (ctx == NULL)
		return;

	p = (ldaphost*) ctx->method_data;
	while (p != NULL) {
		ldaphost *q = p;
		p = p->next;
		ldaphost_free(q);
	}
}


static int
ldaplookup_init(X509_LOOKUP *ctx) {
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_init:\n");
#endif
	(void)ctx;
	return(1);
}


static int
ldaplookup_shutdown(X509_LOOKUP *ctx) {
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_shutdown:\n");
#endif
	(void)ctx;
	return(1);
}


static ldaphost*
ldaphost_new(const char *url) {
	ldaphost *p;
	int          ret;

	p = OPENSSL_malloc(sizeof(ldaphost));
	if (p == NULL) return(NULL);

	memset(p, 0, sizeof(ldaphost));

	p->url = OPENSSL_malloc(strlen(url) + 1);
	if (p->url == NULL) goto error;
	strcpy(p->url, url);

	/*ldap://hostport/dn[?attrs[?scope[?filter[?exts]]]] */
	ret = ldap_is_ldap_url(url);
	if (ret < 0) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_NOT_LDAP_URL);
		goto error;
	}

	ret = ldap_url_parse(p->url, &p->ldapurl);
	if (ret != 0) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_INVALID_URL);
		openssl_add_ldap_error(ret);
		goto error;
	}
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaphost_new: ldap_url_desc2str=%s\n", ldap_url_desc2str(p->ldapurl));
fprintf(stderr, "TRACE_BY_LDAP ldaphost_new: ldapurl->%s://%s:%d\n", p->ldapurl->lud_scheme, p->ldapurl->lud_host, p->ldapurl->lud_port);
#endif

	/* open ldap connection */
#ifdef HAVE_LDAP_INITIALIZE
	ret = ldap_initialize(&p->ld, p->url);
	if (ret != LDAP_SUCCESS) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_INITIALIZATION_ERROR);
		openssl_add_ldap_error(ret);
		goto error;
	}
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaphost_new: ldap_initialize(..., url=%s)\n", p->url);
#endif
#else /*ndef HAVE_LDAP_INITIALIZE*/
	p->ld = ldap_init(p->ldapurl->lud_host, p->ldapurl->lud_port);
	if(p->ld == NULL) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_INITIALIZATION_ERROR);
		goto error;
	}
#endif /*ndef HAVE_LDAP_INITIALIZE*/

	{
		int version = -1;

		ret = ldap_get_option(p->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (ret != LDAP_OPT_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION );
			goto error;
		}
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaphost_new: using ldap v%d protocol\n", version);
#endif
	}

	return(p);
error:
	ldaphost_free(p);
	return(NULL);
}


static void
ldaphost_free(ldaphost *p) {
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaphost_free:\n");
#endif
	if (p == NULL) return;
	if (p->url    != NULL) OPENSSL_free(p->url);
	if (p->binddn != NULL) OPENSSL_free(p->binddn);
	if (p->bindpw != NULL) OPENSSL_free(p->bindpw);
	if (p->ldapurl != NULL) {
		ldap_free_urldesc(p->ldapurl);
		p->ldapurl = NULL;
	}
	if (p->ld != NULL) {
		/* how to free ld ???*/
		p->ld = NULL;
	}
	OPENSSL_free(p);
}


static int/*bool*/
ldaplookup_add_search(X509_LOOKUP *ctx, const char *url) {
	ldaphost *p, *q;

	if (ctx == NULL) return(0);
	if (url == NULL) return(0);

	q = ldaphost_new(url);
	if (q == NULL) return(0);

	p = (ldaphost*) ctx->method_data;
	if (p == NULL) {
		ctx->method_data = (void*) q;
		return(1);
	}

	for(; p->next != NULL; p = p->next) {
		/*find list end*/
	}
	p->next = q;

	return(1);
}


static int/*bool*/
ldaplookup_set_protocol(X509_LOOKUP *ctx, const char *ver) {
	ldaphost *p;
	char *q = NULL;
	int n;

#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_set_protocol(..., %s)\n", ver);
#endif
	if (ctx == NULL) return(0);
	if (ver == NULL) return(0);

	p = (ldaphost*) ctx->method_data;
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_set_protocol(..., %s) p=%p\n", ver, (void*)p);
#endif
	if (p == NULL) return(0);

	n = (int) strtol(ver, &q, 10);
	if (*q != '\0') return(0);
	if ((n < LDAP_VERSION_MIN) || (n > LDAP_VERSION_MAX)) return(0);

	for(; p->next != NULL; p = p->next) {
		/*find list end*/
	}
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_set_protocol(...): ver=%d\n", n);
#endif
	{
		int ret;
		const int version = n;

		ret = ldap_set_option(p->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (ret != LDAP_OPT_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_SET_PROTOCOL, X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION);
			openssl_add_ldap_error(ret);
			return(0);
		}
	}

	return(1);
}


static char*
ldaplookup_attr(ASN1_STRING *nv) {
	char *p = NULL;
	int k;
	BIO *mbio;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return(NULL);

	k = ASN1_STRING_print_ex(mbio, nv, XN_FLAG_RFC2253);
	p = OPENSSL_malloc(k + 1);
	if (p == NULL) goto done;

	k = BIO_read(mbio, p, k);
	p[k] = '\0';

done:
	BIO_free_all(mbio);
	return(p);
}


static char*
ldaplookup_filter(X509_NAME *name, const char *attribute) {
	char *p = NULL;
	int k;
	BIO *mbio;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return(NULL);

	BIO_puts(mbio, "(&");

	k = sk_X509_NAME_ENTRY_num(name->entries);
	for (--k; k >= 0; k--) {
		X509_NAME_ENTRY *ne;
		ASN1_STRING     *nv;
		int nid;

		ne = sk_X509_NAME_ENTRY_value(name->entries, k);
		nid = OBJ_obj2nid(ne->object);

		if (
			(nid != NID_organizationName) &&
			(nid != NID_organizationalUnitName) &&
			(nid != NID_commonName)
		) continue;

		BIO_puts(mbio, "(");
		BIO_puts(mbio, OBJ_nid2sn(nid));
		BIO_puts(mbio, "=");
		nv = ne->value;
#if 0
		/*
		TODO:
		we must escape '(' and ')' symbols and might to check for other symbols (>=128?)
		BIO_puts(mbio, M_ASN1_STRING_data(nv));
		*/
		{	/* escape '(' and ')' */
			p = (char*)M_ASN1_STRING_data(nv);
			for (; *p; p++) {
				if ((*p == '(') || (*p == ')'))
					BIO_write(mbio, "\\", 1);
				BIO_write(mbio, p, 1);
			}
		}
#else
		{
			char *q, *s;

			q = ldaplookup_attr(nv);
			if (q == NULL) goto done;
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_filter: ldaplookup_attr(nv) return '%.512s'\n", q);
#endif
			/* escape some charecters according to RFC2254 */
			for (s=q; *s; s++) {
				if ((*s == '*') ||
				    (*s == '(') ||
				    (*s == ')')
				    /* character '\' should be already escaped ! */
				) {
					/* RFC2254 recommendation */
					BIO_printf(mbio, "\\%02X", (int)*s);
					continue;
				}
				BIO_write(mbio, s, 1);
			}

			OPENSSL_free(q);
		}
#endif
		BIO_puts(mbio, ")");
	}

	BIO_puts(mbio, "(");
	BIO_puts(mbio, attribute);
	BIO_puts(mbio, "=*)");

	BIO_puts(mbio, ")");
	(void)BIO_flush(mbio);

	k = BIO_pending(mbio);
	p = OPENSSL_malloc(k + 1);
	if (p == NULL) goto done;

	k = BIO_read(mbio, p, k);
	p[k] = '\0';
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_filter: p=%.512s\n", p);
#endif

done:
	BIO_free_all(mbio);
	return(p);
}


static int/*bool*/
ldaplookup_check_attr(
	int type,
	const char *attr
) {
	if (type == X509_LU_X509)
		return(strncmp(attr, ATTR_CACERT, sizeof(ATTR_CACERT)) != 0);

	if (type == X509_LU_CRL)
		return(strncmp(attr, ATTR_CACRL, sizeof(ATTR_CACRL)) != 0);

	return(0);
}


/*
 * We will put into store X509 object from passed data in buffer only
 * when object name match passed. To compare both names we use our
 * method "ssh_X509_NAME_cmp"(it is more general).
 */
static int/*bool*/
ldaplookup_data2store(
	int         type,
	X509_NAME*  name,
	void*       buf,
	int         len,
	X509_STORE* store
) {
	int ok = 0;
	BIO *mbio;

	if (name == NULL) return(0);
	if (buf == NULL) return(0);
	if (len <= 0) return(0);
	if (store == NULL) return(0);

	mbio = BIO_new_mem_buf(buf, len);
	if (mbio == NULL) return(0);

	switch (type) {
	case X509_LU_X509: {
		X509 *x509 = d2i_X509_bio(mbio, NULL);
		if(x509 == NULL) goto exit;

		/*This is correct since lookup method is by subject*/
		if (ssh_X509_NAME_cmp(name, X509_get_subject_name(x509)) != 0) goto exit;

		ok = X509_STORE_add_cert(store, x509);
		} break;
	case X509_LU_CRL: {
		X509_CRL *crl = d2i_X509_CRL_bio(mbio, NULL);
		if(crl == NULL) goto exit;

		if (ssh_X509_NAME_cmp(name, X509_CRL_get_issuer(crl)) != 0) goto exit;

		ok = X509_STORE_add_crl(store, crl);
		} break;
	}

exit:
	if (mbio != NULL) BIO_free_all(mbio);
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_data2store: ok=%d\n", ok);
#endif
	return(ok);
}


static int
ldaplookup_result2store(
	int          type,
	X509_NAME*   name,
	LDAP*        ld,
	LDAPMessage* res,
	X509_STORE*  store
) {
	int count = 0;
	int result;
	LDAPMessage *entry;

	result = ldap_count_entries(ld, res);
	if (result < 0) {
		X509byLDAPerr(X509byLDAP_F_RESULT2STORE, X509byLDAP_R_UNABLE_TO_COUNT_ENTRIES);
		ldaplookup_parse_result (ld, res);
		goto done;
	}
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_result2store: ldap_count_entries=%d\n", result);
#endif

	for(entry = ldap_first_entry(ld, res);
	    entry != NULL;
	    entry = ldap_next_entry(ld, entry)
	) {
		char *attr;
		BerElement *ber;
#ifdef TRACE_BY_LDAP
{
char *dn = ldap_get_dn(ld, entry);
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_result2store(): ldap_get_dn=%s\n", dn);
ldap_memfree(dn);
}
#endif
		for(attr = ldap_first_attribute(ld, entry, &ber);
		    attr != NULL;
		    attr = ldap_next_attribute(ld, entry, ber)
		) {
			struct berval **vals;
			struct berval **p;

#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_result2store: attr=%s\n", attr);
#endif
			if (!ldaplookup_check_attr(type, attr))	continue;

			vals = ldap_get_values_len(ld, entry, attr);
			if (vals == NULL) continue;

			for(p = vals; *p; p++) {
				struct berval *q = *p;
				if (ldaplookup_data2store(type, name, q->bv_val, q->bv_len, store)) {
					count++;
				}
			}
			ldap_value_free_len(vals);
		}
		ber_free(ber, 0);
	}
done:
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_result2store: count=%d\n", count);
#endif
	return(count);
}


static int
ldaplookup_by_subject(
	X509_LOOKUP *ctx,
	int          type,
	X509_NAME   *name,
	X509_OBJECT *ret
) {
	int count = 0;
	ldaphost *lh;
	const char *attrs[2];
	char *filter = NULL;


	if (ctx == NULL) return(0);
	if (name == NULL) return(0);

	lh = (ldaphost*) ctx->method_data;
	if (lh == NULL) return(0);

	switch(type) {
	case X509_LU_X509: {
		attrs[0] = ATTR_CACERT;
		} break;
	case X509_LU_CRL: {
		attrs[0] = ATTR_CACRL;
		} break;
	default: {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_WRONG_LOOKUP_TYPE);
		goto done;
		}
	}
	attrs[1] = NULL;

	filter = ldaplookup_filter(name, attrs[0]);
	if (filter == NULL) {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_GET_FILTER);
		goto done;
	}
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_by_subject: filter=%s\n", filter);
#endif

	for (; lh != NULL; lh = lh->next) {
		LDAPMessage *res = NULL;
		int result;

#ifdef TRACE_BY_LDAP
{
int version = -1;

ldap_get_option(lh->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_by_subject:"
" bind to \"%s://%s:%d\""
" using ldap v%d protocol\n"
, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
, version
);
}
#endif

		result = ldaplookup_bind_s(lh->ld);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_BIND);
			{
				char	buf[1024];
				snprintf(buf, sizeof(buf),
					" url=\"%s://%s:%d\""
					" ldaperror=0x%x(%.256s)"
					, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
					, result, ldap_err2string(result)
				);
				ERR_add_error_data(1, buf);
			}
			continue;
		}

		result = ldaplookup_search_s(lh->ld, lh->ldapurl->lud_dn,
				LDAP_SCOPE_SUBTREE, filter, (char**)attrs, 0, &res);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_SEARCH_FAIL);
			ldap_msgfree(res);
			continue;
		}

		result = ldaplookup_result2store(type, name, lh->ld, res, ctx->store_ctx);
		if (result > 0) count += result;

		ldap_msgfree(res);

		/*do not call ldap_unbind_s*/
	}

#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_by_subject: count=%d\n", count);
#endif
	if (count > 0) {
		/*
		 * we have added at least one to the cache so now pull one out again
		 */
		union {
			struct {
				X509_CINF st_x509_cinf;
				X509 st_x509;
			} x509;
			struct {
				X509_CRL_INFO st_crl_info;
				X509_CRL st_crl;
			} crl;
		} data;

		X509_OBJECT stmp, *tmp;
		int k;

		memset(&data, 0, sizeof(data));
		stmp.type = type;
		switch(type) {
		case X509_LU_X509: {
			data.x509.st_x509_cinf.subject = name;
			data.x509.st_x509.cert_info = &data.x509.st_x509_cinf;
			stmp.data.x509 = &data.x509.st_x509;
			} break;
		case X509_LU_CRL: {
			data.crl.st_crl_info.issuer = name;
			data.crl.st_crl.crl = &data.crl.st_crl_info;
			stmp.data.crl = &data.crl.st_crl;
			} break;
		default:
			count = 0;
			goto done;
		}

		CRYPTO_r_lock(CRYPTO_LOCK_X509_STORE);
		k = sk_X509_OBJECT_find(ctx->store_ctx->objs, &stmp);
		if (k >= 0)
			tmp = sk_X509_OBJECT_value(ctx->store_ctx->objs, k);
		else
			tmp = NULL;
		CRYPTO_r_unlock(CRYPTO_LOCK_X509_STORE);
#ifdef TRACE_BY_LDAP
fprintf(stderr, "TRACE_BY_LDAP ldaplookup_by_subject: k=%d, tmp=%p\n", k, (void*)tmp);
#endif

		if (tmp == NULL) {
			count = 0;
			goto done;
		}

		ret->type = tmp->type;
		memcpy(&ret->data, &tmp->data, sizeof(ret->data));
	}

done:
	if (filter != NULL) OPENSSL_free(filter);
	return(count > 0);
}
