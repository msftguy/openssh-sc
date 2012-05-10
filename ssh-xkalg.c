/*
 * Copyright (c) 2005,2010,2011 Roumen Petrov.  All rights reserved.
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

#include "ssh-xkalg.h"
#include <string.h>

#include "log.h"
#include "key.h"
#include "xmalloc.h"


#define SHARAW_DIGEST_LENGTH (2*SHA_DIGEST_LENGTH)


#ifdef OPENSSL_NO_DSA
#  error "OPENSSL_NO_DSA"
#endif
#ifdef OPENSSL_NO_SHA
#  error "OPENSSL_NO_SHA"
#endif


/* NOTE:
 * DSARAW digest is marked as allowed in FIPS mode.
 * This is not enough for FIPS capable OpenSSL 0.9.8x and code block use of
 * DSA_do_{sign|verify}. Quote from openssl 0.9.8 dsa.h header:
 * ----
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 * ----
 * So this application will set DSA_FLAG_NON_FIPS_ALLOW .
 */
#undef USE_DSA_FLAG_NON_FIPS_ALLOW
#ifdef OPENSSL_FIPS
#if OPENSSL_VERSION_NUMBER >= 0x00908000L && OPENSSL_VERSION_NUMBER < 0x10000000L
#  define USE_DSA_FLAG_NON_FIPS_ALLOW
#endif
#endif


#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#define EVP_PKEY_DSARAW_method	\
	(evp_sign_method *)DSARAW_sign, \
	(evp_verify_method *)DSARAW_verify, \
	{EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,EVP_PKEY_DSA4,0}
#else
#define EVP_PKEY_DSARAW_method	\
	DSARAW_sign,DSARAW_verify, \
	{EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,EVP_PKEY_DSA4,0}
#endif


static int/*bool*/
DSARAW_sign(
	int type,
	const unsigned char *dgst,
	int dlen,
	unsigned char *sigret, unsigned int *siglen,
	DSA *dsa
) {
	int ret = 0;
	DSA_SIG *sig = NULL;
#ifdef USE_DSA_FLAG_NON_FIPS_ALLOW
	int dsa_flags = 0;
#endif

	(void) type;
#ifdef TRACE_XKALG
logit("TRACE_XKALG DSARAW_sign:");
#endif

#ifdef USE_DSA_FLAG_NON_FIPS_ALLOW
	dsa_flags = dsa->flags;
	if(FIPS_mode() && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
		dsa->flags |= DSA_FLAG_NON_FIPS_ALLOW;
	}
#endif
	sig = DSA_do_sign(dgst, dlen, dsa);
#ifdef USE_DSA_FLAG_NON_FIPS_ALLOW
	dsa->flags = dsa_flags;
#endif
	if (sig == NULL) {
		*siglen=0;
		return(ret);
	}

	*siglen = SHARAW_DIGEST_LENGTH;
	if (sigret != NULL) {
		u_int rlen, slen;
		rlen = BN_num_bytes(sig->r);
		slen = BN_num_bytes(sig->s);
		if (rlen > SHA_DIGEST_LENGTH || slen > SHA_DIGEST_LENGTH) {
			error("DSARAW_sign: bad sig size %u %u", rlen, slen);
			goto done;
		}
		memset(sigret, 0, SHARAW_DIGEST_LENGTH);
		BN_bn2bin(sig->r, sigret + SHARAW_DIGEST_LENGTH - SHA_DIGEST_LENGTH - rlen);
		BN_bn2bin(sig->s, sigret + SHARAW_DIGEST_LENGTH - slen);
	}
	ret = 1;

done:
	DSA_SIG_free(sig);
	return(ret);
}


static int
DSARAW_verify(
	int type,
	const unsigned char *dgst, int dgst_len,
	const unsigned char *sigbuf, int siglen,
	DSA *dsa
) {
	int ret = -1;
	DSA_SIG *sig = NULL;
#ifdef USE_DSA_FLAG_NON_FIPS_ALLOW
	int dsa_flags;
#endif

	(void) type;
#ifdef TRACE_XKALG
logit("TRACE_XKALG DSARAW_verify: siglen=%d", siglen);
#endif
	if (siglen != SHARAW_DIGEST_LENGTH) return(ret);

	sig = DSA_SIG_new();
	if (sig == NULL) return(ret);

	sig->r = BN_new();
	if (sig->r == NULL)
		fatal("DSARAW_verify: BN_new failed");
	sig->s = BN_new();
	if (sig->s == NULL)
		fatal("DSARAW_verify: BN_new failed");

	BN_bin2bn(sigbuf                  , SHA_DIGEST_LENGTH, sig->r);
	BN_bin2bn(sigbuf+SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, sig->s);

#ifdef USE_DSA_FLAG_NON_FIPS_ALLOW
	dsa_flags = dsa->flags;
	if (FIPS_mode() && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
		dsa->flags |= DSA_FLAG_NON_FIPS_ALLOW;
	}
#endif
	ret = DSA_do_verify(dgst, dgst_len, sig, dsa);
#ifdef USE_DSA_FLAG_NON_FIPS_ALLOW
	dsa->flags = dsa_flags;
#endif

	DSA_SIG_free(sig);
	return(ret);
}


#ifdef HAVE_EVP_MD_FLAGS
#ifndef EVP_MD_FLAG_FIPS
/*openssl 0.9.7+*/
#  define EVP_MD_FLAG_FIPS 0
#endif
#endif /*def HAVE_EVP_MD_FLAGS*/

static
EVP_MD dss1_md = {
	NID_dsa,
	NID_dsaWithSHA1,
	SHA_DIGEST_LENGTH,
#ifdef HAVE_EVP_MD_FLAGS
	EVP_MD_FLAG_FIPS,
#endif /*def HAVE_EVP_MD_FLAGS*/
	NULL, /* (*init) */
	NULL, /* (*update) */
	NULL, /* (*final) */
#ifdef HAVE_EVP_MD_COPY
	NULL,
#endif /*def HAVE_EVP_MD_COPY*/
#ifdef HAVE_EVP_MD_CLEANUP
	NULL,
#endif /*def HAVE_EVP_MD_CLEANUP*/
	EVP_PKEY_DSARAW_method,
	SHA_CBLOCK,
	sizeof(EVP_MD *)+sizeof(SHA_CTX),
#ifdef HAVE_EVP_MD_MD_CTRL
	NULL /*md_ctrl*/
#endif /*def HAVE_EVP_MD_MD_CTRL*/
};


extern const EVP_MD*
EVP_dss1raw(void);


const EVP_MD*
EVP_dss1raw(void) {
	if (dss1_md.init == NULL) {
		const EVP_MD *o = EVP_dss1();
		dss1_md.init    = o->init;
		dss1_md.update  = o->update;
		dss1_md.final   = o->final;
	}
	return(&dss1_md);
}


/* SSH X509 public key algorithms*/
static int x509keyalgs_initialized = 0;
static SSHX509KeyAlgs x509keyalgs[10];


static void
initialize_xkalg(void) {
	SSHX509KeyAlgs *p = x509keyalgs;
	int k;

	if (x509keyalgs_initialized) return;

#ifdef TRACE_XKALG
logit("TRACE_XKALG initialize_xkalg:");
#endif
	k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	for (; k > 0; k--, p++) {
		p->type = KEY_UNSPEC;
		p->name = NULL;
		p->dgst.name = NULL;
		p->dgst.evp = NULL;
		p->signame = NULL;
	}
	x509keyalgs_initialized = 1;
}


static void
add_default_xkalg(void) {
#ifdef TRACE_XKALG
logit("TRACE_XKALG add_default_xkalg:");
#endif

	/*RSA public key algorithm*/
		/* OpenSSH defaults note that
		 * draft-ietf-secsh-transport-NN.txt where NN <= 12
		 * don't define signature format
		 * Stating from v7.1 first is rsa-sha1
		 */
	if (ssh_add_x509key_alg("x509v3-sign-rsa,rsa-sha1") < 0)
		fatal("ssh_init_xkalg: oops");
#ifdef OPENSSL_FIPS
	if(!FIPS_mode())
#endif
	if (ssh_add_x509key_alg("x509v3-sign-rsa,rsa-md5") < 0)
		fatal("ssh_init_xkalg: oops");

#if 0
		/* "draft-ietf-secsh-x509-NN.txt" where NN <= 03 */
/* NOT YET FULLY IMPLEMENTED */
	if (ssh_add_x509key_alg("x509v3-sign-rsa-sha1,rsa-sha1,ssh-rsa") < 0)
		fatal("ssh_init_xkalg: oops");
#endif

	/*DSA public key algorithm*/
		/* OpenSSH default compatible with
		 * draft-ietf-secsh-transport-NN.txt where NN <= 12
		 */
	if (ssh_add_x509key_alg("x509v3-sign-dss,dss-asn1") < 0)
		fatal("ssh_init_xkalg: oops");
		/* some non OpenSSH implementations incompatible with
		 * draft-ietf-secsh-transport-NN.txt where NN <= 12
		 */
	if (ssh_add_x509key_alg("x509v3-sign-dss,dss-raw") < 0)
		fatal("ssh_init_xkalg: oops");

#if 0
		/* draft-ietf-secsh-x509-NN.txt where NN <= 03 */
/* NOT YET FULLY IMPLEMENTED */
	if (ssh_add_x509key_alg("x509v3-sign-dss-sha1,dss-raw,ssh-dss") < 0)
		fatal("ssh_init_xkalg: oops");
#endif
}


void
fill_default_xkalg(void) {
	SSHX509KeyAlgs *p = x509keyalgs;

#ifdef TRACE_XKALG
logit("TRACE_XKALG fill_default_xkalg:");
#endif
	initialize_xkalg();
	if (p[0].name == NULL) add_default_xkalg();
}


static const EVP_MD*
ssh_evp_md(const char *dgstname) {
	if (dgstname == NULL) {
		fatal("ssh_get_md: dgstname is NULL");
		return(NULL); /*unreachable code*/
	}

	if (strcasecmp("rsa-sha1", dgstname) == 0) return(EVP_sha1());
	if (strcasecmp("rsa-md5" , dgstname) == 0) return(EVP_md5());
/*?:	if (strcasecmp("ssh-rsa" , dgstname) == 0) return(EVP_sha1());*/

	if (strcasecmp("dss-asn1", dgstname) == 0) return(EVP_dss1());
	if (strcasecmp("dss-raw" , dgstname) == 0) return(EVP_dss1raw());
/*?:	if (strcasecmp("ssh-dss" , dgstname) == 0) return(EVP_dss1raw());*/

#if 0
	fatal("ssh_get_md: invalid sigformat '%.10s'", dgstname);
#endif
	return(NULL); /*unreachable code*/
}


int
ssh_add_x509key_alg(const char *data) {
	char *name, *mdname, *signame;
	SSHX509KeyAlgs* p;
	const EVP_MD* md;

	if (data == NULL) {
		error("ssh_add_x509pubkey_alg: data is NULL");
		return(-1);
	}

	name = xstrdup(data); /*fatal on error*/

	mdname = strchr(name, ',');
	if (mdname == NULL) {
		error("ssh_add_x509pubkey_alg: cannot get digest");
		goto err;
	}
	*mdname++ = '\0';

	signame = strchr(mdname, ',');
	if (signame != NULL) *signame++ = '\0';

	md = ssh_evp_md(mdname);
	if (md == NULL) {
		error("ssh_add_x509pubkey_alg: unsupported digest");
		goto err;
	}

	initialize_xkalg();
	p = x509keyalgs;
	{
		int k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

		for (; k > 0; k--, p++) {
			if (p->name == NULL) break;
		}
		if (k <= 0) {
			error("ssh_add_x509pubkey_alg: insufficient slots");
			goto err;
		}
	}

	if ((md == EVP_dss1()) || (md == EVP_dss1raw())) {
		p->type = KEY_X509_DSA;
	} else {
		p->type = KEY_X509_RSA;
	}
#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
		if ((md->flags & EVP_MD_FLAG_FIPS) == 0) {
			error("ssh_add_x509pubkey_alg:"
				" %s in not enabled in FIPS mode ", mdname);
			goto err;
		}
	}
#endif
	p->name = name;
	p->dgst.name = mdname;
	p->dgst.evp = md;
	p->signame = signame;

	return (1);

err:
	xfree((void*)name);
	return (-1);
}


int/*bool*/
ssh_is_x509signame(const char *signame) {
	SSHX509KeyAlgs *xkalg;
	int k;

	if (signame == NULL) {
		fatal("ssh_is_x509signame: signame is NULL");
		return(0); /*unreachable code*/
	}

	initialize_xkalg();
	xkalg = x509keyalgs;
	k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

	for (; k > 0; k--, xkalg++) {
		if (xkalg->name == NULL) return(0);
		if (strcmp(signame, X509PUBALG_SIGNAME(xkalg)) == 0) return(1);
	}
	return(0);
}


int
ssh_xkalg_nameind(const char *name, SSHX509KeyAlgs **q, int loc) {
	int k, n;
	SSHX509KeyAlgs *p;

	if (name == NULL) return (-1);

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	if (k < n) p = &x509keyalgs[k];

	for (; k < n; k++, p++) {
		if (p->name == NULL) return(-1);
		if (strcmp(p->name, name) == 0) {
			if (q) *q = p;
			return(k);
		}
	}
	return(-1);
}


int
ssh_xkalg_typeind(int type, SSHX509KeyAlgs **q, int loc) {
	int k, n;
	SSHX509KeyAlgs *p;

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	if (k < n) p = &x509keyalgs[k];

	for (; k < n; k++, p++) {
		if (p->name == NULL) return(-1);
		if (p->type == type) {
			if (q) *q = p;
			return(k);
		}
	}
	return(-1);
}


void
ssh_list_xkalg(int type, Buffer *b) {
	SSHX509KeyAlgs *xkalg;
	int loc;

	if ((type != KEY_X509_RSA) && (type != KEY_X509_DSA)) {
		error("ssh_list_xkalg: %d is not x509 key", type);
		return;
	}
	if (b == NULL) {
		error("ssh_list_xkalg: buffer is NULL");
		return;
	}

#if 1
	/* add only(!) first found */
	loc = ssh_xkalg_typeind(type, &xkalg, -1);
	if (loc < 0) return;

	if (buffer_len(b) > 0) buffer_append(b, ",", 1);
	buffer_append(b, xkalg->name, strlen(xkalg->name));
#else
IMPORTANT NOTE:
  For every unique "key name" we MUST define unique "key type"
otherwise cannot distinguish them !
As example structure Kex contain integer attribute "kex_type"
and kex use method "load_host_key" to find hostkey. When client
request hostkey algorithms (comma separated list with names)
server should be able to find first hostkey that match one of them.
Note to "load_host_key" is assigned method "get_hostkey_by_type"
defined in "sshd.c".

	for (
	    loc = ssh_xkalg_typeind(type, &xkalg, -1);
	    loc >= 0;
	    loc = ssh_xkalg_typeind(type, &xkalg, loc)
	) {
		const char *p;
		int dupl, k;

		p = xkalg->name;

		dupl = 0;

		for (
		    k = ssh_xkalg_typeind(type, &xkalg, -1);
		    (k >= 0) && (k < loc);
		    k = ssh_xkalg_typeind(type, &xkalg, k)
		) {
			if (strcmp(p, xkalg->name) == 0) {
				dupl = 1;
				break;
			}
		}
		if (dupl) continue;

		if (buffer_len(b) > 0) buffer_append(b, ",", 1);
		buffer_append(b, p, strlen(p));
	}
#endif
}
