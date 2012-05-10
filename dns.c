/* $OpenBSD$ */

/*
 * Copyright (c) 2003 Wesley Griffin. All rights reserved.
 * Copyright (c) 2003 Jakob Schlyter. All rights reserved.
 *
 * X.509 certificates support:
 * Copyright (c) 2005,2011 Roumen Petrov.  All rights reserved.
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
#include <sys/socket.h>

#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "xmalloc.h"
#include "key.h"
#include "ssh-x509.h"
#include "uuencode.h"
#include "dns.h"
#include "log.h"


struct ssh_dns_cert_param_s {
	int     cert_type;
	int     key_tag;
	int     algo;
	u_char *cert_data;
	size_t  cert_len;
	u_char *b64_data;
	size_t  b64_len;
};

typedef struct ssh_dns_cert_param_s ssh_dns_cert_param;


static const char *errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

static const char *
dns_result_totext(unsigned int res)
{
	switch (res) {
	case ERRSET_SUCCESS:
		return errset_text[ERRSET_SUCCESS];
	case ERRSET_NOMEMORY:
		return errset_text[ERRSET_NOMEMORY];
	case ERRSET_FAIL:
		return errset_text[ERRSET_FAIL];
	case ERRSET_INVAL:
		return errset_text[ERRSET_INVAL];
	case ERRSET_NONAME:
		return errset_text[ERRSET_NONAME];
	case ERRSET_NODATA:
		return errset_text[ERRSET_NODATA];
	default:
		return "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 */
static int
dns_read_key(u_int8_t *algorithm, u_int8_t *digest_type,
    u_char **digest, u_int *digest_len, Key *key)
{
	int success = 0;

	switch (key->type) {
	case KEY_RSA:
		*algorithm = SSHFP_KEY_RSA;
		break;
	case KEY_DSA:
		*algorithm = SSHFP_KEY_DSA;
		break;
	/* XXX KEY_ECDSA */
	default:
		*algorithm = SSHFP_KEY_RESERVED; /* 0 */
	}

	if (*algorithm) {
		*digest_type = SSHFP_HASH_SHA1;
		*digest = key_fingerprint_raw(key, SSH_FP_SHA1, digest_len);
		if (*digest == NULL)
			fatal("dns_read_key: null from key_fingerprint_raw()");
		success = 1;
	} else {
		*digest_type = SSHFP_HASH_RESERVED;
		*digest = NULL;
		*digest_len = 0;
		success = 0;
	}

	return success;
}

static void
cert_param_clean(ssh_dns_cert_param *param) {
	if (param == NULL) return;

	if (param->cert_data) {
		param->cert_len = 0;
		xfree(param->cert_data);
		param->cert_data = NULL;
	}
	if (param->b64_data) {
		param->b64_len = 0;
		xfree(param->b64_data);
		param->b64_data = NULL;
	}
}

static const char*
bind_cert_type(const ssh_dns_cert_param *param) {
	switch(param->cert_type) {
	case DNS_CERT_TYPE_PKIX: return("PKIX");
#if 0
	case DNS_CERT_TYPE_SPKI: return("SPKI");
	case DNS_CERT_TYPE_PGP : return("PGP");
	case DNS_CERT_TYPE_URI : return("URI");
	case DNS_CERT_TYPE_OID : return("OID");
#endif
	default:
		break;
	}
	return("<UNSUPPORTED>");
}

static const char*
bind_key_algo(const ssh_dns_cert_param *param) {
	switch(param->algo) {
#if 0
	case DNS_KEY_ALGO_UNKNOWN: /*specific case for CERT RR*/
				    return("????");
#endif
	case DNS_KEY_ALGO_RSAMD5  : return("RSAMD5");
	case DNS_KEY_ALGO_DSA     : return("DSA");
	}
	return("<UNSUPPORTED>");
}

static u_int16_t
calc_dns_key_tag(X509 *x509) {
	/* [RFC 2535] Appendix C: Key Tag Calculation */

	/* TODO: to be implemented or not ?
	 * I'm happy without this.
	 */
	return(1);
}

static u_int8_t
get_dns_sign_algo(X509 *x509) {
	int rsa_algo = DNS_KEY_ALGO_UNKNOWN;
	int algo_nid;

	X509_CINF *ci;
	X509_ALGOR *sig;
	ASN1_OBJECT *alg;

	if (x509 == NULL) goto done;

	ci = x509->cert_info;
	if (ci == NULL) goto done;

	sig = ci->signature;
	if (sig == NULL) goto done;

	alg = sig->algorithm;
	if (alg == NULL) goto done;

	algo_nid = OBJ_obj2nid(alg);
	debug3("get_dns_sign_algo: nid=%d(%s)\n", algo_nid, OBJ_nid2ln(algo_nid));

	switch(algo_nid) {
	case NID_md5WithRSAEncryption:
		rsa_algo = DNS_KEY_ALGO_RSAMD5;
		break;
	case NID_sha1WithRSAEncryption:
	case NID_md2WithRSAEncryption:
	case NID_md4WithRSAEncryption:
	case NID_ripemd160WithRSA:
		/* not defined in [RFC 2535] ! */
		rsa_algo = DNS_KEY_ALGO_UNKNOWN;
		break;
	case NID_dsaWithSHA1:
		rsa_algo = DNS_KEY_ALGO_DSA;
		break;
	default:
		rsa_algo = DNS_KEY_ALGO_UNKNOWN;
	}

done:
	return(rsa_algo);
}

/*
 * Read CERT parameters from key buffer.
 */
static int/*bool*/
dns_read_cert(ssh_dns_cert_param *param, const Key *key)
{
	int   ret = 0;
	X509 *x509 = NULL;
	BIO  *bio = NULL;
	int   k = 0;

	if (param == NULL) goto done;
	if (key   == NULL) goto done;
	if (!key_is_x509(key)) goto done;
		
	x509 = key->x509;
	if (x509 == NULL) goto done;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) goto done;

	i2d_X509_bio(bio, x509);
	(void)BIO_flush(bio);

	cert_param_clean(param);

	k = BIO_pending(bio);
	param->cert_data = xmalloc(k + 1); /*fatal on error*/
	param->cert_len = BIO_read(bio, param->cert_data, k);

	k = param->cert_len << 1;
	param->b64_data = xmalloc(k); /*fatal on error*/
	param->b64_len = uuencode(param->cert_data, param->cert_len, (char*)param->b64_data, k);

	param->algo = get_dns_sign_algo(x509);
	param->key_tag = calc_dns_key_tag(x509);
	param->cert_type = DNS_CERT_TYPE_PKIX;

	ret = 1;

done:
	if (bio) BIO_free_all(bio);
	return(ret);
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
static int
dns_read_rdata(u_int8_t *algorithm, u_int8_t *digest_type,
    u_char **digest, u_int *digest_len, u_char *rdata, int rdata_len)
{
	int success = 0;

	*algorithm = SSHFP_KEY_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	if (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		if (*digest_len > 0) {
			*digest = (u_char *) xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} else {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	return success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
static int
is_numeric_hostname(const char *hostname)
{
	struct addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	if (hostname == NULL) {
		error("is_numeric_hostname called with NULL hostname");
		return -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	if (getaddrinfo(hostname, NULL, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		return -1;
	}

	return 0;
}

/*
 * Read CERT parameters from rdata buffer.
 */
static int/*bool*/
dns_read_cert_rdata(ssh_dns_cert_param *param, u_char *rdata, int rdata_len)
{
	size_t len ;

	cert_param_clean(param);

	if (rdata_len < 5) return(0);

	param->cert_type = (rdata[0] << 8) + rdata[1];
	param->key_tag   = (rdata[2] << 8) + rdata[3];
	param->algo      = rdata[4];

	len = rdata_len - 5;
	param->cert_len = len;
	if (len > 0) {
		param->cert_data = (u_char *) xmalloc(len);
		memcpy(param->cert_data, rdata + 5, len);
	}
	return(1);
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
static int
verify_hostcert_dns(const char *hostname, const Key *hostkey, int *flags)
{
	u_int counter;
	int result;
	struct rrsetinfo *certs = NULL;

	ssh_dns_cert_param hostkey_param;
	ssh_dns_cert_param dnskey_param;

	debug3("verify_hostcert_dns");

	memset(&hostkey_param, 0, sizeof(hostkey_param));
	memset(&dnskey_param , 0, sizeof(dnskey_param ));

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_CERT, 0, &certs);
	if (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		return(-1);
	}

	if (certs->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure certificates in DNS",
		    certs->rri_nrdatas);
	} else {
		debug("found %d insecure certificates in DNS",
		    certs->rri_nrdatas);
	}

	/* Initialize host key parameters */
	if (!dns_read_cert(&hostkey_param, hostkey)) {
		error("Error calculating host key certificate.");
		cert_param_clean(&hostkey_param);
		freerrset(certs);
		return(-1);
	}

	if (certs->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	for (counter = 0 ; counter < certs->rri_nrdatas ; counter++)  {
		Key* dns_cert = NULL;
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted certificates.
		 */
		if (!dns_read_cert_rdata(&dnskey_param,
		    certs->rri_rdatas[counter].rdi_data,
		    certs->rri_rdatas[counter].rdi_length
		)) {
			verbose("Error parsing certificate from DNS.");
			goto next;
		}

		if (hostkey_param.cert_type != dnskey_param.cert_type) continue;

		/* We will skip useless "key tag" */

		/* We will ignore "algorithm" since number of
		 * algorithms defined in [RFC 2535] is limited.
		 */
		dns_cert = x509key_from_blob(dnskey_param.cert_data, dnskey_param.cert_len);
		if (dns_cert == NULL) {
			verbose("Invalid certificate from DNS.");
			goto next;
		}
		if (X509_cmp(hostkey->x509, dns_cert->x509) == 0) {
			*flags |= DNS_VERIFY_MATCH;
		}
		key_free(dns_cert);
		dns_cert = NULL;

next:
		cert_param_clean(&dnskey_param);
	}

	cert_param_clean(&hostkey_param);
	freerrset(certs);

	if (*flags & DNS_VERIFY_FOUND)
		if (*flags & DNS_VERIFY_MATCH)
			debug("matching host key certificate found in DNS");
		else
			debug("mismatching host key certificate found in DNS");
	else
		debug("no host key certificate found in DNS");

	return(0);
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
int
verify_host_key_dns(const char *hostname, struct sockaddr *address,
    Key *hostkey, int *flags)
{
	u_int counter;
	int result;
	struct rrsetinfo *fingerprints = NULL;

	u_int8_t hostkey_algorithm;
	u_int8_t hostkey_digest_type;
	u_char *hostkey_digest;
	u_int hostkey_digest_len;

	u_int8_t dnskey_algorithm;
	u_int8_t dnskey_digest_type;
	u_char *dnskey_digest;
	u_int dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	if (hostkey == NULL)
		fatal("No key to look up!");

	if (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		return -1;
	}

	if ((hostkey->type == KEY_X509_RSA) || (hostkey->type == KEY_X509_DSA)) {
		result = verify_hostcert_dns(hostname, hostkey, flags);
		if (*flags & DNS_VERIFY_FOUND) {
			return(result);
		}
		/*try to found SSHFP RR*/
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	if (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		return -1;
	}

	if (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} else {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	/* Initialize host key parameters */
	if (!dns_read_key(&hostkey_algorithm, &hostkey_digest_type,
	    &hostkey_digest, &hostkey_digest_len, hostkey)) {
		error("Error calculating host key fingerprint.");
		freerrset(fingerprints);
		return -1;
	}

	if (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	for (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		if (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			continue;
		}

		/* Check if the current key is the same as the given key */
		if (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_type == dnskey_digest_type) {

			if (hostkey_digest_len == dnskey_digest_len &&
			    memcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {

				*flags |= DNS_VERIFY_MATCH;
			}
		}
		xfree(dnskey_digest);
	}

	xfree(hostkey_digest); /* from key_fingerprint_raw() */
	freerrset(fingerprints);

	if (*flags & DNS_VERIFY_FOUND)
		if (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		else
			debug("mismatching host key fingerprint found in DNS");
	else
		debug("no host key fingerprint found in DNS");

	return 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
int
export_dns_rr(const char *hostname, Key *key, FILE *f, int generic)
{
	u_int8_t rdata_pubkey_algorithm = 0;
	u_int8_t rdata_digest_type = SSHFP_HASH_SHA1;
	u_char *rdata_digest;
	u_int rdata_digest_len;
	ssh_dns_cert_param cert_param;

	u_int i;
	int success = 0;

	memset(&cert_param, 0, sizeof(cert_param));

	if (dns_read_cert(&cert_param, key)) {
		u_char *p;
		int k;

		if (generic || (cert_param.algo == DNS_KEY_ALGO_UNKNOWN)) {
			fprintf(f, "%s\tIN\tTYPE%d \\# %d %04x %04x %02x (\n\t"
			    , hostname
			    , DNS_RDATATYPE_CERT
			    , (int)(5 + cert_param.cert_len)
			    , cert_param.cert_type
			    , cert_param.key_tag
			    , cert_param.algo
			);
			p = cert_param.cert_data;
			i = cert_param.cert_len;
			k = 32;
			for (; i > 0; i--, p++) {
				fprintf(f, "%02x", (int) *p);
				if (--k <= 0) {
					fprintf(f, "\n\t");
					k = 32;
				}
			}
		} else {
			fprintf(f, "%s\tIN\tCERT\t%s %d %s (\n\t"
			    , hostname
			    , bind_cert_type(&cert_param)
			    , cert_param.key_tag
			    , bind_key_algo(&cert_param)
			);
			p = cert_param.b64_data;
			i = cert_param.b64_len;
			k = 64;
			for (; i > 0; i--, p++) {
				fprintf(f, "%c", *p);
				if (--k <= 0) {
					fprintf(f, "\n\t");
					k = 64;
				}
			}
		}
		fprintf(f, "\n\t)\n");
		success = 1;
	} else
	if (dns_read_key(&rdata_pubkey_algorithm, &rdata_digest_type,
	    &rdata_digest, &rdata_digest_len, key)) {

		if (generic)
			fprintf(f, "%s IN TYPE%d \\# %d %02x %02x ", hostname,
			    DNS_RDATATYPE_SSHFP, 2 + rdata_digest_len,
			    rdata_pubkey_algorithm, rdata_digest_type);
		else
			fprintf(f, "%s IN SSHFP %d %d ", hostname,
			    rdata_pubkey_algorithm, rdata_digest_type);

		for (i = 0; i < rdata_digest_len; i++)
			fprintf(f, "%02x", rdata_digest[i]);
		fprintf(f, "\n");
		xfree(rdata_digest); /* from key_fingerprint_raw() */
		success = 1;
	} else {
		error("export_dns_rr: unsupported algorithm");
	}

	cert_param_clean(&cert_param);
	return success;
}
