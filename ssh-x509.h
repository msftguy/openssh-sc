#ifndef SSH_X509_H
#define SSH_X509_H
/*
 * Copyright (c) 2002-2005 Roumen Petrov.  All rights reserved.
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
#include "key.h"
#include "buffer.h"


#ifndef SSH_X509STORE_DISABLED
/*
 * Method return a key(x509) only with "Subject"("Distinguished Name") !
 */
Key*	x509key_from_subject(int _keytype, const char* _cp);
#endif /*ndef SSH_X509STORE_DISABLED*/


Key*	x509key_from_blob(const u_char *blob, int blen);
int	x509key_to_blob(const Key *key, Buffer *b);

char*	x509key_subject(const Key *key);

/*
 * Method write x509 certificate as blob.
 */
int	x509key_write(const Key *key, FILE *f);
#ifndef SSH_X509STORE_DISABLED
/*
 * Method write x509 certificate subject.
 */
int	x509key_write_subject(const Key *key, FILE *f);
int	x509key_write_subject2(const Key *key, const char *keyname, FILE *f);
#endif /*ndef SSH_X509STORE_DISABLED*/

/*
 * The patched configure script define OPENSSH_KEYS_USE_BIO
 * depending from OpenSSH version
 */

#ifdef OPENSSH_KEYS_USE_BIO
Key*	x509key_parse_cert(Key *key, BIO *bio);
#else
Key*	x509key_load_cert(Key *key, FILE *fp);
#endif

#ifdef OPENSSH_KEYS_USE_BIO
int	x509key_write_bio_pem(BIO *bio, const Key *key, const EVP_CIPHER *cipher, u_char *passphrase, int len);
#else
int	x509key_save_pem(FILE *fp, const Key *key, const EVP_CIPHER *cipher, u_char *passphrase, int len);
#endif

#ifndef SSH_X509STORE_DISABLED
int	ssh_x509_equal(const Key *a, const Key *b);
#endif /*ndef SSH_X509STORE_DISABLED*/

int		ssh_x509key_type(const char *name);
const char*	ssh_x509key_name(const Key *k);

int	ssh_x509_sign(const Key *key, u_char **psignature, u_int *psignaturelen, const u_char *data, u_int datalen);
int	ssh_x509_verify(const Key *key, const u_char *signature, u_int signaturelen, const u_char *data, u_int datalen);
u_int	ssh_x509_key_size(const Key *key);


#endif /* SSH_X509_H */
