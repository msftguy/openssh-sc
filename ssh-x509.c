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

#include "ssh-x509.h"
#include <ctype.h>
#include <string.h>

#include "ssh-xkalg.h"
#include "log.h"
#include "xmalloc.h"
#include "uuencode.h"
#include <openssl/pem.h>
#include "x509store.h"
#include "compat.h"
#include "evp-compat.h"

#ifndef ISSPACE
#  define ISSPACE(ch) (isspace((int)(unsigned char)(ch)))
#endif

int (*pssh_x509cert_check)(X509 *_cert) = NULL;


int
ssh_X509_NAME_print(BIO* bio, X509_NAME *xn) {
	static u_long print_flags =	((XN_FLAG_ONELINE & \
					  ~XN_FLAG_SPC_EQ & \
					  ~XN_FLAG_SEP_MASK) | \
					 XN_FLAG_SEP_COMMA_PLUS);

	if (xn == NULL) return(-1);

	X509_NAME_print_ex(bio, xn, 0, print_flags);
	(void)BIO_flush(bio);

	return(BIO_pending(bio));
}


char*
ssh_X509_NAME_oneline(X509_NAME *xn) {
	char *buf = NULL;
	int size;
	BIO* mbio = NULL;

	if (xn == NULL) return(NULL);

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return(buf);

	size = ssh_X509_NAME_print(mbio, xn);
	if (size <= 0) {
		error("ssh_X509_NAME_oneline: no data in buffer");
		goto done;
	}

	buf = xmalloc(size + 1); /*fatal on error*/

	/* we should request one byte more !?!? */
	if (size != BIO_gets(mbio, buf, size + 1)) {
		error("ssh_X509_NAME_oneline: cannot get data from buffer");
		goto done;
	}
	buf[size] = '\0';

done:
	/* This call will walk the chain freeing all the BIOs */
	BIO_free_all(mbio);

	return(buf);
}


int/*bool*/
key_is_x509(const Key *k) {
	if (k == NULL) return(0);

	if ( (k->type == KEY_X509_RSA) ||
	     (k->type == KEY_X509_DSA) ) {
		return(1);
	}

	return(0);
}


#ifndef SSH_X509STORE_DISABLED
static const char*
x509key_find_subject(const char* s) {
	static const char *keywords[] = {
		"subject",
		"distinguished name",
		"distinguished-name",
		"distinguished_name",
		"distinguishedname",
		"dn",
		NULL
	};
	const char **q, *p;
	size_t len;

	if (s == NULL) {
		error("x509key_find_subject: no input data");
		return(NULL);
	}
	for (; *s && ISSPACE(*s); s++)
	{/*skip space*/}

	for (q=keywords; *q; q++) {
		len = strlen(*q);
		if (strncasecmp(s, *q, len) != 0) continue;

		for (p = s + len; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		if (!*p) {
			error("x509key_find_subject: no data after keyword");
			return(NULL);
		}
		if (*p == ':' || *p == '=') {
			for (p++; *p && ISSPACE(*p); p++)
			{/*skip space*/}
			if (!*p) {
				error("x509key_find_subject: no data after separator");
				return(NULL);
			}
		}
		if (*p == '/' || *p == ',') {
			/*skip leading [Relative]DistinguishedName elements separator*/
			for (p++; *p && ISSPACE(*p); p++)
			{/*skip space*/}
			if (!*p) {
				error("x509key_find_subject: no data");
				return(NULL);
			}
		}
		return(p);
	}
	return(NULL);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static unsigned long
ssh_hctol(u_char ch) {
/* '0'-'9' = 0x30 - 0x39 (ascii) */
/* 'A'-'F' = 0x41 - 0x46 (ascii) */
/* 'a'-'f' = 0x61 - 0x66 (ascii) */
/* should work for EBCDIC */
	if (('0' <= ch) && (ch <= '9')) {
		return((long)(ch - '0'));
	}
	if (('A' <= ch) && (ch <= 'F')) {
		return((long)(ch - ('A' - 10)));
	}
	if (('a' <= ch) && (ch <= 'f')) {
		return((long)(ch - ('a' - 10)));
	}

	return(-1);
}


static unsigned long
ssh_hatol(const u_char *str, size_t maxsize) {
	int k;
	long v, ret = 0;

	for(k = maxsize; k > 0; k--, str++) {
		v = ssh_hctol(*str);
		if (v < 0) return(-1);
		ret = (ret << 4) + v;
	}
	return(ret);
}


static int
get_escsymbol(const u_char* str, size_t len, u_long *value) {
	const char ch = *str;
	long v;

	if (len < 1) {
		error("get_escsymbol:"
		" missing characters in escape sequence");
		return(-1);
	}

	/*escape formats:
		"{\\}\\W%08lX"
		"{\\}\\U%04lX"
		"{\\}\\%02X"
		"{\\}\\x%02X" - X509_NAME_oneline format
	*/
	if (ch == '\\') {
		if (value) *value = ch;
		return(1);
	}
	if (ch == 'W') {
		if (len < 9) {
			error("get_escsymbol:"
			" to short 32-bit escape sequence");
			return(-1);
		}
		v = ssh_hatol(++str, 8);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 32-bit hex sequence");
			 return(-1);
		}
		if (value) *value = v;
		return(9);
	}
	if (ch == 'U') {
		if (len < 5) {
			error("get_escsymbol:"
			" to short 16-bit escape sequence");
			return(-1);
		}
		v = ssh_hatol(++str, 4);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 16-bit hex sequence");
			 return(-1);
		}
		if (value) *value = v;
		return(5);
	}
#if 0
/*
The code bellow isn't correct. Let 'O' is not 8-bit string(as example
BMPString) then "X509_NAME_oneline" will output "\x00O"(!).
The X509_NAME_oneline output format will left unsupported, i.e.:
Unsupported:
$ openssl x509 -in cert_file -subject -noout
Supported:
  v0.9.7+
$ openssl x509 -in cert_file -subject -noout -nameopt oneline[,<more_name_options>]
  v0.9.6
$ openssl x509 -in cert_file -subject -noout -nameopt oneline [-nameopt <other_name_option>]
*/
	if ((ch == 'x') || (ch == 'X')) {
		if (len < 3) {
			error("get_escsymbol:"
			" to short 8-bit hex sequence");
			return(-1);
		}
		v = ssh_hatol(++str, 2);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 8-bit hex sequence");
			 return(-1);
		}
		if (value) *value = v;
		return(3);
	}
#endif
	v = ssh_hctol(*str);
	if (v < 0) {
		/*a character is escaped ?*/
		if (*str > 127) { /*ASCII comparision !*/
			/* there is no reason symbol above 127
                           to be escaped in this way */
			error("get_escsymbol:"
			" non-ascii character in escape sequence");
			return(-1);
		}
		if (value) *value = *str;
		return(1);
	}

	/*two hex numbers*/
	{
		long vlo;
		if (len < 2) {
			error("get_escsymbol:"
			" to short 8-bit escape sequence");
			return(-1);
		}
		vlo = ssh_hctol(*++str);
		if (vlo < 0) {
			error("get_escsymbol:"
			" invalid character in 8-bit hex sequence");
			 return(-1);
		}
		v = (v << 4) + vlo;
	}
	if (value) *value = v;
	return(2);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static int/*bool*/
ssh_X509_NAME_add_entry_by_NID(X509_NAME* name, int nid, const u_char* str, size_t len) {
/* default maxsizes:
  C: 2
  L, ST: 128
  O, OU, CN: 64
  emailAddress: 128
*/
	u_char  buf[129*6+1]; /*enough for 128 UTF-8 symbols*/
	int     ret = 0;
	int     type = MBSTRING_ASC;
	u_long  ch;
	u_char *p;
	const u_char *q;
	size_t  k;

	/*this is internal method and we don't check validity of some arguments*/

	p = buf;
	q = str;
	k = sizeof(buf);

	while ((len > 0) && (k > 0)) {
		int ch_utf8 = 1;
		if (*q == '\0') {
			error("ssh_X509_NAME_add_entry_by_NID:"
			" unsupported zero(NIL) symbol in name");
			return(0);
		}
		if (*q == '\\') {
			len--;
			if (len <= 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" escape sequence without data");
				return(0);
			}

			ret = get_escsymbol(++q, len, &ch);
			if (ret < 0) return(0);
			if (ret == 2) {
				/*escaped two hex numbers*/
				ch_utf8 = 0;
			}
		} else {
			ret = UTF8_getc(q, len, &ch);
			if(ret < 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" cannot get next symbol(%.32s)"
				, q);
				return(0);
			}
		}
		len -= ret;
		q += ret;

		if (ch_utf8) {
			/* UTF8_putc return negative if buffer is too short */
			ret = UTF8_putc(p, k, ch);
			if (ret < 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" UTF8_putc fail for symbol %ld", ch);
				return(0);
			}
		} else {
			*p = (u_char)ch;
			ret = 1;
		}
		k -= ret;
		p += ret;
	}
	if (len > 0) {
		error("ssh_X509_NAME_add_entry_by_NID:"
		" too long data");
		return(0);
	}
	*p = '\0';

	for (p = buf; *p; p++) {
		if (*p > 127) {
			type = MBSTRING_UTF8;
			break;
		}
	}
	k = strlen((char*)buf);

	debug3("ssh_X509_NAME_add_entry_by_NID:"
		" type=%s, k=%d"
		, ((type == MBSTRING_ASC) ? "ASCII" : "UTF-8")
		, (int)k
	);

	/* this method will fail if string exceed max size limit for nid */
	ret = X509_NAME_add_entry_by_NID(name, nid, type, buf, (int)k, -1, 0);
	if (!ret) {
		char ebuf[1024];
		error("ssh_X509_NAME_add_entry_by_NID: X509_NAME_add_entry_by_NID"
		" fail with errormsg='%.*s'"
		" for nid=%d/%.32s"
		" and data='%.512s'"
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf))
		, nid, OBJ_nid2ln(nid)
		, str);
	}
	return(ret);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static int/*bool*/
x509key_str2X509NAME(const char* _str, X509_NAME *_name) {
	int   ret = 1;
	char *str = NULL;
	char *p, *q, *token;
	int   has_more = 0;

	str = xmalloc(strlen(_str) + 1); /*fatal on error*/
	strcpy(str, _str);

	p = (char*)str;
	while (*p) {
		int nid;
		for (; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		if (!*p) break;

		/* get shortest token */
		{
			char *tokenA = strchr(p, ',');
			char *tokenB = strchr(p, '/');

			if (tokenA == NULL) {
				token = tokenB;
			} else if (tokenB == NULL) {
				token = tokenA;
			} else {
				token = (tokenA < tokenB) ? tokenA : tokenB;
			}
		}
		if (token) {
			has_more = 1;
			*token = 0;
		} else {
			has_more = 0;
			token = p + strlen(p);
		}
		q = strchr(p, '=');
		if (!q) {
			error("x509key_str2X509NAME: cannot parse '%.200s' ...", p);
			ret = 0;
			break;
		}
		{
			char *s = q;
			for(--s; ISSPACE(*s) && (s > p); s--)
			{/*skip trailing space*/}
			*++s = 0;
		}
		nid = OBJ_txt2nid(p);
#ifdef SSH_OPENSSL_DN_WITHOUT_EMAIL
		if (nid == NID_undef) {
			/* work around for OpenSSL 0.9.7+ */
			if (strcasecmp(p, "Email") == 0) {
				nid = OBJ_txt2nid("emailAddress");
			}
		}
#endif /* def SSH_OPENSSL_DN_WITHOUT_EMAIL */
		if (nid == NID_undef) {
			error("x509key_str2X509NAME: cannot get nid from string '%.200s'", p);
			ret = 0;
			break;
		}

		p = q + 1;
		if (!*p) {
			error("x509key_str2X509NAME: no data");
			ret = 0;
			break;
		}

		for (; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		for (q = token - 1; (q >= p) && ISSPACE(*q); q--)
		{/*skip unexpected \n, etc. from end*/}
		*++q = 0;

		ret = ssh_X509_NAME_add_entry_by_NID(_name, nid, (u_char*)p, (size_t)(q - p));
		if (!ret) {
			break;
		}

		p = token;
		if (has_more) p++;
	}

	if (str) xfree(str);
	debug3("x509key_str2X509NAME: return %d", ret);
	return(ret);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
Key*
x509key_from_subject(int _keytype, const char* _cp) {
	int         ret = 1;
	Key*        key = NULL;
	X509_NAME  *subj;
	const char *subject;

	if (_keytype != KEY_X509_RSA &&
	    _keytype != KEY_X509_DSA) {
		debug3("x509key_from_subject: %d is not x509 key", _keytype);
		return(NULL);
	}
	debug3("x509key_from_subject(%d, [%.1024s]) called",
		_keytype, (_cp ? _cp : ""));
	subject = x509key_find_subject(_cp);
	if (subject == NULL)
		return(NULL);

	debug3("x509key_from_subject: subject=[%.1024s]", subject);
	key = key_new(_keytype);
	if (key == NULL) {
		error("x509key_from_subject: out of memory");
		return(NULL);
	}

	if (ret > 0) {
		subj = X509_get_subject_name(key->x509);
		if (subj == NULL) {
			error("x509key_from_subject: new x509 key without subject");
			ret = 0;
		}
	}

	if (ret > 0) {
		ret = x509key_str2X509NAME(subject, subj);
	}

	if (ret <= 0) {
		if (key != NULL) {
			key_free(key);
			key = NULL;
		}
	}
	debug3("x509key_from_subject: return %p", (void*)key);
	return(key);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


static Key*
x509_to_key(X509 *x509) {
	Key      *key = NULL;
	EVP_PKEY *env_pkey;

	env_pkey = X509_get_pubkey(x509);
	if (env_pkey == NULL) {
		char ebuf[256];
		error("x509_to_key: X509_get_pubkey fail %.*s",
			(int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		return(NULL);
	}
	/*else*/
	debug3("x509_to_key: X509_get_pubkey done!");

	switch (env_pkey->type) {
	case EVP_PKEY_RSA:
		key = key_new(KEY_UNSPEC);
		key->x509 = x509;
		key->rsa = EVP_PKEY_get1_RSA(env_pkey);
		key->type = KEY_X509_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, key->rsa, 8);
#endif
		break;

	case EVP_PKEY_DSA:
		key = key_new(KEY_UNSPEC);
		key->x509 = x509;
		key->dsa = EVP_PKEY_get1_DSA(env_pkey);
		key->type = KEY_X509_DSA;
#ifdef DEBUG_PK
		DSA_print_fp(stderr, key->dsa, 8);
#endif
		break;

	default:
		fatal("ssh_x509_key_size: unknow env_pkey->type %d", env_pkey->type);
		/*unreachable code*/
	}

	return(key);
}


Key*
x509key_from_blob(const u_char *blob, int blen) {
	Key* key = NULL;
	BIO *mbio;

	if (blob == NULL) return(NULL);
	if (blen <= 0) return(NULL);

	/* convert blob data to BIO certificate data */
	mbio = BIO_new_mem_buf(blob, blen);
	if (mbio == NULL) return(NULL);

	debug3("x509key_from_blob: We have %d bytes available in BIO", BIO_pending(mbio));

	{ /* read X509 certificate from BIO data */
		X509* x509 = NULL;
		x509 = d2i_X509_bio(mbio, NULL);
		if (x509 == NULL) {
			/* We will print only debug info !!!
			 * This method is used in place where we can only check incomming data.
			 * If data contain x506 certificate blob we will return a key otherwise NULL.
			 */
			char ebuf[256];
			debug3("x509key_from_blob: read X509 from BIO fail %.*s",
				(int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		} else {
			key = x509_to_key(x509);
			if (key == NULL)
				X509_free(x509);
		}
	}

	/* This call will walk the chain freeing all the BIOs */
	BIO_free_all(mbio);
	return(key);
}


static int
x509key_check(const char* method, const Key *key) {
	if (key == NULL)
		{ error("%.50s: no key", method); return(0); }

	if (!key_is_x509(key))
		{ error("%.50s: cannot handle key type %d", method, key->type); return(0); }

	if (key->x509 == NULL)
		{ error("%.50s: no X509 key", method); return(0); }

	return(1);
}


int
x509key_to_blob(const Key *key, Buffer *b) {
	int     len;
	void   *str;
	u_char *p;

	if (!x509key_check("x509key_to_blob", key)) return(0);

	len = i2d_X509(key->x509, NULL);
	str = xmalloc(len); /*fatal on error*/
	p = str;
	i2d_X509(key->x509, &p);
	buffer_append(b, str, len);
	xfree(str);
	return(1);
}


char*
x509key_subject(const Key *key) {
	X509_NAME *dn;

	if (!x509key_check("x509key_subject", key)) return(NULL);

	/* it is better to match format used in x509key_write_subject */
	dn = X509_get_subject_name(key->x509);
	return(ssh_X509_NAME_oneline(dn)); /*fatal on error*/
}


int
x509key_write(const Key *key, FILE *f) {
	int    ret = 0;
	Buffer b;
	size_t n;

	if (!x509key_check("x509key_write_blob", key)) return(ret);

	buffer_init(&b);
	ret = x509key_to_blob(key, &b);
	if (ret) {
		/* write ssh key name */
		const char *ktype = key_ssh_name(key);
		n = strlen(ktype);
		ret = ( fwrite(ktype, 1, n, f) == n ) &&
		      ( fwrite(" ", 1, 1, f) == 1 );
	}
	if (ret) {
		char uu[1<<12]; /* 4096 bytes */

		n = uuencode(buffer_ptr(&b), buffer_len(&b), uu, sizeof(uu));
		ret = n > 0;
		if (ret) {
			ret = (fwrite(uu, 1, n, f) ==  n);
		}
	}
	buffer_free(&b);
	return(ret);
}


#ifndef SSH_X509STORE_DISABLED
int
x509key_write_subject(const Key *key, FILE *f) {
	return(x509key_write_subject2(key, key_ssh_name(key), f));
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
int
x509key_write_subject2(const Key *key, const char *keyname, FILE *f) {
	BIO  *out;

	if (!x509key_check("x509key_write_subject2", key)) return(0);
	if (keyname == NULL) return(0);

	out = BIO_new_fp(f, BIO_NOCLOSE);
	if (out == NULL) return(0);
#ifdef VMS
	{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
	}
#endif

	BIO_puts(out, keyname);
	BIO_puts(out, " Subject:");
	ssh_X509_NAME_print(out, X509_get_subject_name(key->x509));

	BIO_free_all(out);
	return(1);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


Key*
#ifdef OPENSSH_KEYS_USE_BIO
x509key_parse_cert(Key *key, BIO *bio) {
#else
x509key_load_cert(Key *key, FILE *fp) {
#endif
	if (key == NULL) return(NULL);

	if ( (key->type == KEY_RSA) ||
	     (key->type == KEY_DSA) ) {
#ifdef OPENSSH_KEYS_USE_BIO
		key->x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
#else
		key->x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#endif
		if (key->x509 == NULL) {
			char ebuf[256];
			debug3("%s: PEM_read_X509 fail %.*s",
				__func__, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		}
		else {
			key->type = (key->type == KEY_RSA) ? KEY_X509_RSA : KEY_X509_DSA;
			debug("read X509 certificate done: type %.40s", key_type(key));
		}
	}
	return(key);
}


static int
#ifdef OPENSSH_KEYS_USE_BIO
x509key_write_bio_cert(BIO *out, X509 *x509) {
#else
x509key_save_cert(FILE *fp, X509 *x509) {
#endif
	int  ret = 0;
#ifndef OPENSSH_KEYS_USE_BIO
	BIO *out;

	out = BIO_new_fp(fp, BIO_NOCLOSE);
	if (out == NULL) return(0);
#ifdef VMS
	{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
	}
#endif
#endif /*ndef OPENSSH_KEYS_USE_BIO*/

	BIO_puts(out, "issuer= ");
	ssh_X509_NAME_print(out, X509_get_issuer_name(x509));
	BIO_puts(out, "\n");

	BIO_puts(out, "subject= ");
	ssh_X509_NAME_print(out, X509_get_subject_name(x509));
	BIO_puts(out, "\n");

	{
		const char *alstr = (const char*)X509_alias_get0(x509, NULL);
		if (alstr == NULL) alstr = "<No Alias>";
		BIO_puts(out, alstr);
		BIO_puts(out, "\n");
	}

	ret = PEM_write_bio_X509(out, x509);
	if (!ret) {
		char ebuf[256];
		error("%s: PEM_write_bio_X509 fail %.*s",
			__func__, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
	}

#ifndef OPENSSH_KEYS_USE_BIO
	BIO_free_all(out);
#endif /*ndef OPENSSH_KEYS_USE_BIO*/
	return(ret);
}


int
#ifdef OPENSSH_KEYS_USE_BIO
x509key_write_bio_pem(
	BIO *bio,
#else
x509key_save_pem(
	FILE *fp,
#endif
	const Key *key,
	const EVP_CIPHER *cipher,
	u_char *passphrase,
	int len
) {
	if (!x509key_check("x509key_save_pem", key)) return(0);

	switch (key->type) {
	case KEY_X509_DSA:
#ifdef OPENSSH_KEYS_USE_BIO
		if (PEM_write_bio_DSAPrivateKey(bio, key->dsa, cipher, passphrase, len, NULL, NULL))
			return(x509key_write_bio_cert(bio, key->x509));
#else
		if (PEM_write_DSAPrivateKey(fp, key->dsa, cipher, passphrase, len, NULL, NULL))
			return(x509key_save_cert(fp, key->x509));
#endif
		break;
	case KEY_X509_RSA:
#ifdef OPENSSH_KEYS_USE_BIO
		if (PEM_write_bio_RSAPrivateKey(bio, key->rsa, cipher, passphrase, len, NULL, NULL))
			return(x509key_write_bio_cert(bio, key->x509));
#else
		if (PEM_write_RSAPrivateKey(fp, key->rsa, cipher, passphrase, len, NULL, NULL))
			return(x509key_save_cert(fp, key->x509));
#endif
		break;
	}
	return(0);
}


#ifndef SSH_X509STORE_DISABLED
/*
 * We can check only by Subject (Distinguished Name):
 *   - sshd receive from client only x509 certificate !!!
 *   - sshadd -d ... send only x509 certificate !!!
 *   - otherwise Key might contain private key
 */
int
ssh_x509_equal(const Key *a, const Key *b) {
	if (!x509key_check("ssh_x509_equal", a)) return(1);
	if (!x509key_check("ssh_x509_equal", b)) return(-1);

#if 1
/*
 * We must use own method to compare two X509_NAMEs instead of OpenSSL
 * function[s]! See notes before body of "ssh_X509_NAME_cmp()".
 */
	{
		X509_NAME *nameA = X509_get_subject_name(a->x509);
		X509_NAME *nameB = X509_get_subject_name(b->x509);
		return(ssh_X509_NAME_cmp(nameA, nameB));
	}
#else
	return(X509_subject_name_cmp(a->x509, b->x509));
#endif
}
#endif /*ndef SSH_X509STORE_DISABLED*/


int
ssh_x509key_type(const char *name) {
	SSHX509KeyAlgs *p;
	int k;

	if (name == NULL) {
		fatal("ssh_x509key_type: name is NULL");
		return(KEY_UNSPEC); /*unreachable code*/
	}

	k = ssh_xkalg_nameind(name, &p, -1);
	return((k >= 0) ? p->type : KEY_UNSPEC);
}


static SSHX509KeyAlgs*
ssh_first_xkalg(int type) {
	SSHX509KeyAlgs *p;
	int k;

	k = ssh_xkalg_typeind(type, &p, -1);
	return((k >= 0) ? p : NULL);
}


const char*
ssh_x509key_name(const Key *k) {
	int type;
	SSHX509KeyAlgs *p;

	if (k == NULL) {
		fatal("ssh_x509key_name: key is NULL");
		return(NULL); /*unreachable code*/
	}
	if (!key_is_x509(k)) return(NULL);
	
	type = k->type;
	p = ssh_first_xkalg(type);
	if (p != NULL) return(p->name);

	error("ssh_x509key_name: cannot handle type %d", type);
	return(NULL);
}


int
ssh_x509_sign(
	const Key *key,
	u_char **psignature, u_int *psignaturelen,
	const u_char *data, u_int datalen
) {
	int    ret = -1;
	SSHX509KeyAlgs *xkalg = NULL;
	int  keylen = 0;
	u_char *sigret = NULL;
	u_int  siglen;

	if (!x509key_check("ssh_x509_sign", key)) return(ret);
	if ((key->rsa == NULL) && (key->dsa == NULL)) {
		error("ssh_x509_sign: missing private key");
		return(ret);
	}

	debug3("ssh_x509_sign: key_type=%.20s, key_ssh_name=%.40s", key_type(key), key_ssh_name(key));
	ret = 1;
	{
		EVP_PKEY *privkey = EVP_PKEY_new();
		if (privkey == NULL) {
			error("ssh_x509_sign: out of memory");
			ret = -1;
		}
		else {
			ret = (key->rsa)
				? EVP_PKEY_set1_RSA(privkey, key->rsa)
				: EVP_PKEY_set1_DSA(privkey, key->dsa);

			if (ret <= 0) {
				char ebuf[256];
				error("ssh_x509_sign: EVP_PKEY_set1_XXX: failed %.*s",
					(int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
			}
		}

		if (ret > 0) {
			xkalg = ssh_first_xkalg(key->type);
			if (xkalg == NULL) {
				error("ssh_x509_sign: cannot handle type %d", key->type);
				ret = -1;
			}
		}

		if (ret > 0) {
			keylen = EVP_PKEY_size(privkey);
			if (keylen > 0) {
				sigret = xmalloc(keylen); /*fatal on error*/
			} else {
				error("ssh_x509_sign: cannot get key size for type %d", key->type);
				ret = -1;
			}
		}
		if (ret > 0) {
			EVP_MD_CTX ctx;

			ssh_EVP_MD_CTX_init(&ctx);

			debug3("ssh_x509_sign: alg=%.50s, md=%.30s", xkalg->name, xkalg->dgst.name);
			ret = ssh_EVP_SignInit_ex(&ctx, xkalg->dgst.evp, NULL);
			if (ret <= 0) {
				char ebuf[256];
				error("ssh_x509_sign: EVP_SignInit_ex"
				" fail with errormsg='%.*s'"
				, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
			}
			if (ret > 0) {
				ret = ssh_EVP_SignUpdate(&ctx, data, datalen);
				if (ret <= 0) {
					char ebuf[256];
					error("ssh_x509_sign: EVP_SignUpdate"
					" fail with errormsg='%.*s'"
					, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
				}
			}
			if (ret > 0) {
				ret = EVP_SignFinal(&ctx, sigret, &siglen, privkey);
				debug3("ssh_x509_sign: keylen=%d, siglen=%u", keylen, siglen);
				if (ret <= 0) {
					char ebuf[256];
					error("ssh_x509_sign: digest failed: %.*s",
						(int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
				}
			}
		
			ssh_EVP_MD_CTX_cleanup(&ctx);
		}
		EVP_PKEY_free(privkey);
	}
	if (ret > 0) {
		Buffer b;
		const char *signame;

		buffer_init(&b);
		signame = X509PUBALG_SIGNAME(xkalg);
		debug3("ssh_x509_sign: signame=%.50s", signame);
		buffer_put_cstring(&b, signame);
		buffer_put_string(&b, sigret, siglen);

		{
			u_int  len = buffer_len(&b);
			if (psignaturelen != NULL)
				*psignaturelen = len;

			if (psignature != NULL) {
				*psignature = xmalloc(len); /*fatal on error*/
				memcpy(*psignature, buffer_ptr(&b), len);
			}
		}
		buffer_free(&b);
	}
	if (sigret) {
		memset(sigret, 's', keylen);
		xfree(sigret);
	}
	ret = ret > 0 ? 0 : -1;
	debug3("ssh_x509_sign: return %d", ret);
	return(ret);
}


int
ssh_x509_verify(
	const Key *key,
	const u_char *signature, u_int signaturelen,
	const u_char *data, u_int datalen
) {
	int ret = -1;
	u_char *sigblob = NULL;
	uint len = 0;

	if (!x509key_check("ssh_x509_verify", key)) return(ret);

	{ /* get signature data only */
		Buffer b;

		ret = 1;
		buffer_init(&b);
		buffer_append(&b, signature, signaturelen);

		{ /* check signature format */
			char *sigformat = buffer_get_string(&b, NULL);

			debug3("ssh_x509_verify: signature format = %.40s", sigformat);
			if (!ssh_is_x509signame(sigformat)) {
				error("ssh_x509_verify: cannot handle signature format %.40s", sigformat);
				ret = 0;
			}
			xfree(sigformat);
		}

		if (ret > 0) {
			int rlen;

			sigblob = buffer_get_string(&b, &len);
			rlen = buffer_len(&b);
			if (rlen != 0) {
				error("ssh_x509_verify: remaining bytes in signature %d", rlen);
				ret = -1;
			}
		}
		buffer_free(&b);
	}

	if (ret > 0 ) {
		EVP_PKEY* pubkey = X509_get_pubkey(key->x509);
		SSHX509KeyAlgs *xkalg;
		int loc;

		if (pubkey == NULL) {
			error("ssh_x509_verify: no 'X509 Public Key'");
			ret = -1;
		}
		if (ret > 0) {
			loc = ssh_xkalg_typeind(key->type, &xkalg, -1);
			if (loc < 0) {
				error("ssh_x509_verify: cannot handle type %d", key->type);
				ret = -1;
			}
		}
		if (ret > 0) {
			for (; loc >= 0; loc = ssh_xkalg_typeind(key->type, &xkalg, loc)) {
				EVP_MD_CTX ctx;

				debug3("ssh_x509_verify: md=%.30s, loc=%d", xkalg->dgst.name, loc);
				ret = ssh_EVP_VerifyInit(&ctx, xkalg->dgst.evp);
				if (ret <= 0) {
					char ebuf[256];
					error("ssh_x509_verify: EVP_VerifyInit"
					" fail with errormsg='%.*s'"
					, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
				}
				if (ret > 0) {
					ret = ssh_EVP_VerifyUpdate(&ctx, data, datalen);
					if (ret <= 0) {
						char ebuf[256];
						error("ssh_x509_verify: EVP_VerifyUpdate"
						" fail with errormsg='%.*s'"
						, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
					}
				}
				if (ret > 0)
					ret = EVP_VerifyFinal(&ctx, sigblob, len, pubkey);
			
				ssh_EVP_MD_CTX_cleanup(&ctx);

				if (ret > 0) break;
			}
			if (ret <= 0) {
				debug3("ssh_x509_verify: failed for all digests");
				ret = 0;
			}
		}
		EVP_PKEY_free(pubkey);
	}
	if (sigblob) {
		memset(sigblob, 's', len);
		xfree(sigblob);
		sigblob = NULL;
	}
	if (ret > 0) {
		if (pssh_x509cert_check != NULL) {
			ret = pssh_x509cert_check(key->x509);
		} else {
			error("ssh_x509_verify: pssh_x509cert_check is NULL");
			ret = -1;
		}
	}
	ret = ret > 0 ? 1 : (ret < 0 ? -1 : 0);
	debug3("ssh_x509_verify: return %d", ret);
	return(ret);
}


u_int
ssh_x509_key_size(const Key *key) {
	EVP_PKEY *pkey;
	int k = 0;

	if (!x509key_check("key_size", key)) goto done;

	pkey = X509_get_pubkey(key->x509);
	if (pkey == NULL) goto done;

	switch(pkey->type) {
	case EVP_PKEY_RSA:
		/* BN_num_bits return int (!): XXX */
		k = BN_num_bits(pkey->pkey.rsa->n);
		break;
	case EVP_PKEY_DSA:
		/*OpenSSH like this*/
		k = BN_num_bits(pkey->pkey.dsa->p);
		break;
	default:
		fatal("ssh_x509_key_size: unknow pkey->type %d", pkey->type);
		/*unreachable code*/
	}
	EVP_PKEY_free(pkey);
done:
	return((u_int) k);
}
