#ifndef X509_BY_LDAP_H
#define X509_BY_LDAP_H
/*
 * Copyright (c) 2004 Roumen Petrov.  All rights reserved.
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

/* openssh specific includes */
#include "includes.h"
#ifndef LDAP_ENABLED
#  include "error: LDAP is disabled"
#endif

/* required includes */
#include <openssl/x509_vfy.h>
#include <openssl/err.h>


#ifdef	__cplusplus
extern "C" {
#endif


X509_LOOKUP_METHOD* X509_LOOKUP_ldap(void);

#define X509_L_LDAP_HOST	1
#define X509_L_LDAP_VERSION	2

#define X509_LOOKUP_add_ldap(x,value) \
		X509_LOOKUP_ctrl((x),X509_L_LDAP_HOST,(value),(long)(0),NULL)
#define X509_LOOKUP_set_protocol(x,value) \
		X509_LOOKUP_ctrl((x),X509_L_LDAP_VERSION,(value),(long)(0),NULL)


/* Error codes for the X509byLDAP functions. */
#ifdef NO_ERR /* openssl < 0.7.x */
#  define OPENSSL_NO_ERR /* openssl >= 0.7.x */
#endif

#ifndef OPENSSL_NO_ERR

void ERR_load_X509byLDAP_strings(void);

/* library */
#define ERR_LIB_X509byLDAP	ERR_LIB_USER

#define X509byLDAPerr(f,r) ERR_PUT_error(ERR_LIB_X509byLDAP,(f),(r),__FILE__,__LINE__)

/* BEGIN ERROR CODES */

/* Function codes. */
#define X509byLDAP_F_LOOKUPCRTL			100
#define X509byLDAP_F_LDAPHOST_NEW		101
#define X509byLDAP_F_SET_PROTOCOL		102
#define X509byLDAP_F_RESULT2STORE		103
#define X509byLDAP_F_GET_BY_SUBJECT		104

/* Reason codes. */
#define X509byLDAP_R_INVALID_CRTLCMD			100
#define X509byLDAP_R_NOT_LDAP_URL			101
#define X509byLDAP_R_INVALID_URL			102
#define X509byLDAP_R_INITIALIZATION_ERROR		103
#define X509byLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION	104
#define X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION	105
#define X509byLDAP_R_UNABLE_TO_COUNT_ENTRIES		106
#define X509byLDAP_R_WRONG_LOOKUP_TYPE			107
#define X509byLDAP_R_UNABLE_TO_GET_FILTER		108
#define X509byLDAP_R_UNABLE_TO_BIND			109
#define X509byLDAP_R_SEARCH_FAIL			110

#endif /*ndef OPENSSL_NO_ERR*/


#ifdef	__cplusplus
}
#endif


#endif /*ndef X509_BY_LDAP_H*/
