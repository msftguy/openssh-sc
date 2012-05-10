/* $OpenBSD$ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011 Roumen Petrov.  All rights reserved.
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

#include "includes.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "buffer.h"
#include "compat.h"
#include "log.h"
#include "key.h"
#include "evp-compat.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

/*NOTE; Do not define USE_LEGACY_DSS_... if build
  is with FIPS capable OpenSSL */
/* Define if you want yo use legacy sign code */
#undef USE_LEGACY_DSS_SIGN
/* Define if you want yo use legacy verify code */
#undef USE_LEGACY_DSS_VERIFY


#ifndef USE_LEGACY_DSS_SIGN
/* caller must free result */
static DSA_SIG*
ssh_DSA_sign(DSA *dsa, const u_char *data, u_int datalen)
{
	DSA_SIG *sig = NULL;

	EVP_PKEY *pkey = NULL;
	u_char *tsig = NULL;
	u_int slen, len;
	int ret;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}

	EVP_PKEY_set1_DSA(pkey, dsa);

	slen = EVP_PKEY_size(pkey);
	tsig = xmalloc(slen);	/*fatal on error*/

{
	EVP_MD_CTX md;

	ssh_EVP_MD_CTX_init(&md);

	ret = ssh_EVP_SignInit_ex(&md, EVP_dss1(), NULL);
	if (ret <= 0) {
		char ebuf[256];
		error("%s: EVP_SignInit_ex fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto clean;
	}

	ret = ssh_EVP_SignUpdate(&md, data, datalen);
	if (ret <= 0) {
		char ebuf[256];
		error("%s: EVP_SignUpdate fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto clean;
	}
	
	ret = EVP_SignFinal(&md, tsig, &len, pkey);
	if (ret <= 0) {
		char ebuf[256];
		error("%s: sign failed: %.*s"
		, __func__
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto clean;
	}

clean:
	ssh_EVP_MD_CTX_cleanup(&md);
}

	if (ret > 0) {
		/* decode DSA signature */
		const u_char *psig = tsig;
		sig = d2i_DSA_SIG(NULL, &psig, len);
	}

done:
	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', slen);
		xfree(tsig);
	}

	if (pkey != NULL) EVP_PKEY_free(pkey);

	return sig;
}
#endif /* ndef USE_LEGACY_DSS_SIGN */


int
ssh_dss_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	DSA_SIG *sig;
#ifdef USE_LEGACY_DSS_SIGN
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE];
	u_int dlen;
#endif /*def USE_LEGACY_DSS_SIGN*/
	u_char sigblob[SIGBLOB_LEN];
	u_int rlen, slen, len;
	Buffer b;

	if (key == NULL || key->dsa == NULL || (key->type != KEY_DSA &&
	    key->type != KEY_DSA_CERT && key->type != KEY_DSA_CERT_V00)) {
		error("ssh_dss_sign: no DSA key");
		return -1;
	}

#ifdef USE_LEGACY_DSS_SIGN
	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, data, datalen);
	EVP_DigestFinal(&md, digest, &dlen);

	sig = DSA_do_sign(digest, dlen, key->dsa);
	memset(digest, 'd', sizeof(digest));
#else
	sig = ssh_DSA_sign(key->dsa, data, datalen);
#endif

	if (sig == NULL) {
	#ifdef USE_LEGACY_DSS_SIGN
		error("ssh_dss_sign: sign failed");
	#else
		error("ssh_dss_sign: DSA_sign failed");
	#endif
		return -1;
	}

	rlen = BN_num_bytes(sig->r);
	slen = BN_num_bytes(sig->s);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		error("bad sig size %u %u", rlen, slen);
		DSA_SIG_free(sig);
		return -1;
	}
	memset(sigblob, 0, SIGBLOB_LEN);
	BN_bn2bin(sig->r, sigblob+ SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig->s, sigblob+ SIGBLOB_LEN - slen);
	DSA_SIG_free(sig);

	if (datafellows & SSH_BUG_SIGBLOB) {
		if (lenp != NULL)
			*lenp = SIGBLOB_LEN;
		if (sigp != NULL) {
			*sigp = xmalloc(SIGBLOB_LEN);
			memcpy(*sigp, sigblob, SIGBLOB_LEN);
		}
	} else {
		/* ietf-drafts */
		buffer_init(&b);
		buffer_put_cstring(&b, "ssh-dss");
		buffer_put_string(&b, sigblob, SIGBLOB_LEN);
		len = buffer_len(&b);
		if (lenp != NULL)
			*lenp = len;
		if (sigp != NULL) {
			*sigp = xmalloc(len);
			memcpy(*sigp, buffer_ptr(&b), len);
		}
		buffer_free(&b);
	}
	return 0;
}


#ifndef USE_LEGACY_DSS_VERIFY
static int
ssh_DSA_verify(DSA *dsa, DSA_SIG *sig, const u_char *data, u_int datalen)
{
	int ret = -1;
	u_char *tsig = NULL;
	u_int len;
	EVP_PKEY *pkey = NULL;

	/* Sig is in DSA_SIG structure, convert to encoded buffer */

	len = i2d_DSA_SIG(sig, NULL);
	tsig = xmalloc(len);	/*fatal on error*/

	{ /* encode a DSA signature */
		u_char *psig = tsig;
		i2d_DSA_SIG(sig, &psig);
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}
	EVP_PKEY_set1_DSA(pkey, dsa);

{ /* now verify signature */
	EVP_MD_CTX md;

	ssh_EVP_MD_CTX_init(&md);

	ret= ssh_EVP_VerifyInit(&md, EVP_dss1());
	if (ret <= 0) {
		char ebuf[256];
		error("%s: EVP_VerifyInit fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto clean;
	}

	ret= ssh_EVP_VerifyUpdate(&md, data, datalen);
	if (ret <= 0) {
		char ebuf[256];
		error("%s: EVP_VerifyUpdate fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto clean;
	}

	ret = EVP_VerifyFinal(&md, tsig, len, pkey);
	if (ret <= 0) {
		char ebuf[256];
		error("%s: EVP_VerifyFinal fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto clean;
	}
clean:
	ssh_EVP_MD_CTX_cleanup(&md);
}

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', len);
		xfree(tsig);
	}

	return ret;
}
#endif /*ndef USE_LEGACY_DSS_VERIFY*/


int
ssh_dss_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	DSA_SIG *sig;
#ifdef USE_LEGACY_DSS_VERIFY
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE];
	u_int dlen;
#endif
	u_char *sigblob;
	u_int len;
	int rlen, ret;
	Buffer b;

	if (key == NULL || key->dsa == NULL || (key->type != KEY_DSA &&
	    key->type != KEY_DSA_CERT && key->type != KEY_DSA_CERT_V00)) {
		error("ssh_dss_verify: no DSA key");
		return -1;
	}

	/* fetch signature */
	if (datafellows & SSH_BUG_SIGBLOB) {
		sigblob = xmalloc(signaturelen);
		memcpy(sigblob, signature, signaturelen);
		len = signaturelen;
	} else {
		/* ietf-drafts */
		char *ktype;
		buffer_init(&b);
		buffer_append(&b, signature, signaturelen);
		ktype = buffer_get_cstring(&b, NULL);
		if (strcmp("ssh-dss", ktype) != 0) {
			error("ssh_dss_verify: cannot handle type %s", ktype);
			buffer_free(&b);
			xfree(ktype);
			return -1;
		}
		xfree(ktype);
		sigblob = buffer_get_string(&b, &len);
		rlen = buffer_len(&b);
		buffer_free(&b);
		if (rlen != 0) {
			error("ssh_dss_verify: "
			    "remaining bytes in signature %d", rlen);
			xfree(sigblob);
			return -1;
		}
	}

	if (len != SIGBLOB_LEN) {
		fatal("bad sigbloblen %u != SIGBLOB_LEN", len);
	}

	/* parse signature */
	if ((sig = DSA_SIG_new()) == NULL)
		fatal("ssh_dss_verify: DSA_SIG_new failed");
	if ((sig->r = BN_new()) == NULL)
		fatal("ssh_dss_verify: BN_new failed");
	if ((sig->s = BN_new()) == NULL)
		fatal("ssh_dss_verify: BN_new failed");
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig->r) == NULL) ||
	    (BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, sig->s) == NULL))
		fatal("ssh_dss_verify: BN_bin2bn failed");

	/* clean up */
	memset(sigblob, 0, len);
	xfree(sigblob);

#ifdef USE_LEGACY_DSS_VERIFY
	/* sha1 the data */
	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, data, datalen);
	EVP_DigestFinal(&md, digest, &dlen);

	ret = DSA_do_verify(digest, dlen, sig, key->dsa);
	memset(digest, 'd', sizeof(digest));
#else
	ret = ssh_DSA_verify(key->dsa, sig, data, datalen);
#endif
	DSA_SIG_free(sig);

	debug("ssh_dss_verify: signature %s",
	    ret == 1 ? "correct" : ret == 0 ? "incorrect" : "error");
	return ret;
}
