#ifndef X509STORE_H
#define X509STORE_H
/*
 * Copyright (c) 2002-2007 Roumen Petrov.  All rights reserved.
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
#include <openssl/x509.h>


int	ssh_X509_NAME_print(BIO* bio, X509_NAME *xn);
char*	ssh_X509_NAME_oneline(X509_NAME *xn);


int ssh_x509cert_check(X509 *_cert);


typedef struct {
	int is_server;
	/* allowed client/server certificate purpose */
	int allowedcertpurpose; /* note field contain purpose index */
#ifndef SSH_X509STORE_DISABLED
	int key_allow_selfissued; /* make sense only when x509store is enabled */
	int mandatory_crl;
#endif /*ndef SSH_X509STORE_DISABLED*/
}       SSH_X509Flags;

extern SSH_X509Flags ssh_x509flags;

void ssh_x509flags_initialize(SSH_X509Flags *flags, int is_server);
void ssh_x509flags_defaults(SSH_X509Flags *flags);

/* return purpose index, not purpose id (!) */
int ssh_get_x509purpose_s(int _is_server, const char* _purpose_synonym);


#ifndef SSH_X509STORE_DISABLED
int	ssh_X509_NAME_cmp(X509_NAME *_a, X509_NAME *_b);
int/*bool*/	ssh_is_selfsigned(X509 *_cert);

int ssh_x509store_lookup(X509_STORE *store, int type, X509_NAME *name, X509_OBJECT *xobj);

typedef struct {
	/* ssh PKI(X509) store */
	const char   *certificate_file;
	const char   *certificate_path;
	const char   *revocation_file;
	const char   *revocation_path;
#ifdef LDAP_ENABLED
	const char   *ldap_ver;
	const char   *ldap_url;
#endif
}       X509StoreOptions;

void ssh_x509store_initialize(X509StoreOptions *options);
void ssh_x509store_system_defaults(X509StoreOptions *options);
void ssh_x509store_user_defaults(X509StoreOptions *options, uid_t uid);

int/*bool*/ ssh_x509store_addlocations(const X509StoreOptions *_locations);

#endif /*ndef SSH_X509STORE_DISABLED*/


#ifdef SSH_X509STORE_DISABLED
#ifdef LDAP_ENABLED
#  include "cannot enable LDAP when x509store is disabled"
#endif /*def LDAP_ENABLED*/
#ifdef SSH_OCSP_ENABLED
#  include "cannot enable OCSP when x509store is disabled"
#endif /*def SSH_OCSP_ENABLED*/
#endif /*def SSH_X509STORE_DISABLED*/


#ifdef SSH_OCSP_ENABLED

enum va_type {
	SSHVA_NONE,
	SSHVA_OCSP_CERT,
	SSHVA_OCSP_SPEC
};


typedef struct {
	int type; /*allowed values from enum va_type*/

	/* file with additional trusted certificates */
	const char *certificate_file;

	/* ssh OCSP Provider(Respoder) URL */
	const char *responder_url;
}       VAOptions;

int ssh_get_default_vatype(void);
int ssh_get_vatype_s(const char* type);

void ssh_set_validator(const VAOptions *_va); /*fatal on error*/

int ssh_ocsp_validate(X509 *cert, X509_STORE *x509store);

#endif /*def SSH_OCSP_ENABLED*/


#endif /* X509STORE_H */
