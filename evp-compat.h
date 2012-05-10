#ifndef EVP_COMPAT_H
#define EVP_COMPAT_H
/*
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
#include <openssl/evp.h>

static inline void
ssh_EVP_MD_CTX_init(EVP_MD_CTX *ctx) {
#ifdef HAVE_EVP_MD_CTX_INIT
	/* OpenSSL >= 0.9.7 */
	EVP_MD_CTX_init(ctx);
#else
	(void) ctx;
#endif
}


static inline int
ssh_EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx) {
#ifdef HAVE_EVP_MD_CTX_INIT
	/* OpenSSL >= 0.9.7 */
	/* Free resources associated with the context(return always true) */
	return EVP_MD_CTX_cleanup(ctx);
#else
	(void) ctx;
	return 1;
#endif
}


static inline int
ssh_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
#ifdef OPENSSL_EVP_DIGESTUPDATE_VOID
	/* OpenSSL < 0.9.7 */
	EVP_VerifyInit(ctx, type);
	return 1;
#else
	return EVP_VerifyInit(ctx, type);
#endif
}


static inline int
ssh_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, u_int cnt) {
#ifdef OPENSSL_EVP_DIGESTUPDATE_VOID
	/* OpenSSL < 0.9.7 */
	EVP_VerifyUpdate(ctx, d, cnt);
	return 1;
#else
	/* NOTE: size_t cnt in OpenSSL >= 0.9.8 */
	return EVP_VerifyUpdate(ctx, d, cnt);
#endif
}


static inline int
ssh_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
#ifdef OPENSSL_EVP_DIGESTUPDATE_VOID
	/* OpenSSL < 0.9.7 */
	EVP_SignInit(ctx, type);
	return 1;
#else
	return EVP_SignInit(ctx, type);
#endif
}


/* NOTE:
 * - EVP_SignInit in openssl 0.9.7+ is equal to:
 *     EVP_MD_CTX_init(ctx);
 *     return EVP_DigestInit_ex(ctx, type, NULL);
 * - EVP_SignInit_ex is define for EVP_DigestInit_ex
 * - also ENGINE exist in openssl-engine-0.9.6x, but function
 *   EVP_SignInit_ex is from 0.9.7+
 */
#ifndef HAVE_OPENSSL_ENGINE_H
struct fake_engine_st {
	const char *id;
};

typedef struct fake_engine_st ENGINE;
#endif


static inline int
ssh_EVP_SignInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
#ifdef HAVE_EVP_MD_CTX_INIT
	/* OpenSSL >= 0.9.7 */
	return EVP_SignInit_ex(ctx, type, impl);
#else
	(void) impl;
	EVP_SignInit(ctx, type);
	return 1;
#endif
}


static inline int
ssh_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, u_int cnt) {
#ifdef OPENSSL_EVP_DIGESTUPDATE_VOID
	/* OpenSSL < 0.9.7 */
	EVP_SignUpdate(ctx, d, cnt);
	return 1;
#else
	/* NOTE: size_t cnt in OpenSSL >= 0.9.8 */
	return EVP_SignUpdate(ctx, d, cnt);
#endif
}


#endif /* ndef EVP_COMPAT_H*/
