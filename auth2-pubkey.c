/* $OpenBSD$ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * X.509 certificates support,
 * Copyright (c) 2003-2006 Roumen Petrov.  All rights reserved.
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
#include <sys/stat.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "pathnames.h"
#include "uidswap.h"
#include "auth-options.h"
#include "canohost.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "ssh-x509.h"
#include "misc.h"
#include "authfile.h"
#include "match.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern u_int session_id2_len;

static int pubkey_algorithm_allowed(int pktype, const char* pkalg);

static int
userauth_pubkey(Authctxt *authctxt)
{
	Buffer b;
	Key *key = NULL;
	char *pkalg;
	u_char *pkblob, *sig;
	u_int alen, blen, slen;
	int have_sig, pktype;
	int authenticated = 0;

	if (!authctxt->valid) {
		debug2("userauth_pubkey: disabled because of invalid user");
		return 0;
	}
	have_sig = packet_get_char();
	if (datafellows & SSH_BUG_PKAUTH) {
		debug2("userauth_pubkey: SSH_BUG_PKAUTH");
		/* no explicit pkalg given */
		pkblob = packet_get_string(&blen);
		buffer_init(&b);
		buffer_append(&b, pkblob, blen);
		/* so we have to extract the pkalg from the pkblob */
		pkalg = buffer_get_string(&b, &alen);
		buffer_free(&b);
	} else {
		pkalg = packet_get_string(&alen);
		pkblob = packet_get_string(&blen);
	}
	pktype = key_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		logit("userauth_pubkey: unsupported public key algorithm: %s",
		    pkalg);
		goto done;
	}
	if (!pubkey_algorithm_allowed(pktype, pkalg)) {
		debug("userauth_pubkey: disallowed public key algorithm: %s",
		    pkalg);
		goto done;
	}
	key = key_from_blob(pkblob, blen);
	if (key == NULL) {
		error("userauth_pubkey: cannot decode key: %s", pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error("userauth_pubkey: type mismatch for decoded key "
		    "(received %d, expected %d)", key->type, pktype);
		goto done;
	}
	if (have_sig) {
		sig = packet_get_string(&slen);
		packet_check_eom();
		buffer_init(&b);
		if (datafellows & SSH_OLD_SESSIONID) {
			buffer_append(&b, session_id2, session_id2_len);
		} else {
			buffer_put_string(&b, session_id2, session_id2_len);
		}
		/* reconstruct packet */
		buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
		buffer_put_cstring(&b, authctxt->user);
		buffer_put_cstring(&b,
		    datafellows & SSH_BUG_PKSERVICE ?
		    "ssh-userauth" :
		    authctxt->service);
		if (datafellows & SSH_BUG_PKAUTH) {
			buffer_put_char(&b, have_sig);
		} else {
			buffer_put_cstring(&b, "publickey");
			buffer_put_char(&b, have_sig);
			buffer_put_cstring(&b, pkalg);
		}
		buffer_put_string(&b, pkblob, blen);
#ifdef DEBUG_PK
		buffer_dump(&b);
#endif
		/* test for correct signature */
		authenticated = 0;
		if (PRIVSEP(user_key_allowed(authctxt->pw, key)) &&
		    PRIVSEP(key_verify(key, sig, slen, buffer_ptr(&b),
		    buffer_len(&b))) == 1)
			authenticated = 1;
		buffer_free(&b);
		xfree(sig);
	} else {
		debug("test whether pkalg/pkblob are acceptable");
		packet_check_eom();

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		if (PRIVSEP(user_key_allowed(authctxt->pw, key))) {
			packet_start(SSH2_MSG_USERAUTH_PK_OK);
			packet_put_string(pkalg, alen);
			packet_put_string(pkblob, blen);
			packet_send();
			packet_write_wait();
			authctxt->postponed = 1;
		}
	}
	if (authenticated != 1)
		auth_clear_options();
done:
	debug2("userauth_pubkey: authenticated %d pkalg %s", authenticated, pkalg);
	if (key != NULL)
		key_free(key);
	xfree(pkalg);
	xfree(pkblob);
	return authenticated;
}

static int
match_principals_option(const char *principal_list, struct KeyCert *cert)
{
	char *result;
	u_int i;

	/* XXX percent_expand() sequences for authorized_principals? */

	for (i = 0; i < cert->nprincipals; i++) {
		if ((result = match_list(cert->principals[i],
		    principal_list, NULL)) != NULL) {
			debug3("matched principal from key options \"%.100s\"",
			    result);
			xfree(result);
			return 1;
		}
	}
	return 0;
}

static int
match_principals_file(char *file, struct passwd *pw, struct KeyCert *cert)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES], *cp, *ep, *line_opts;
	u_long linenum = 0;
	u_int i;

	temporarily_use_uid(pw);
	debug("trying authorized principals file %s", file);
	if ((f = auth_openprincipals(file, pw, options.strict_modes)) == NULL) {
		restore_uid();
		return 0;
	}
	while (read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
		/* Skip leading whitespace. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		if ((ep = strchr(cp, '#')) != NULL)
			*ep = '\0';
		if (!*cp || *cp == '\n')
			continue;
		/* Trim trailing whitespace. */
		ep = cp + strlen(cp) - 1;
		while (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
			*ep-- = '\0';
		/*
		 * If the line has internal whitespace then assume it has
		 * key options.
		 */
		line_opts = NULL;
		if ((ep = strrchr(cp, ' ')) != NULL ||
		    (ep = strrchr(cp, '\t')) != NULL) {
			for (; *ep == ' ' || *ep == '\t'; ep++)
				;
			line_opts = cp;
			cp = ep;
		}
		for (i = 0; i < cert->nprincipals; i++) {
			if (strcmp(cp, cert->principals[i]) == 0) {
				debug3("matched principal \"%.100s\" "
				    "from file \"%s\" on line %lu",
			    	    cert->principals[i], file, linenum);
				if (auth_parse_options(pw, line_opts,
				    file, linenum) != 1)
					continue;
				fclose(f);
				restore_uid();
				return 1;
			}
		}
	}
	fclose(f);
	restore_uid();
	return 0;
}	

/* return 1 if given publickey algorithm is allowed */
static int
pubkey_algorithm_allowed(int pktype, const char* pkalg)
{
	char *s, *cp, *p;
#ifdef OPENSSL_HAS_ECC
	int curve_nid = -1;
#endif

	if (options.pubkey_algorithms == NULL) return(1);

	s = cp = xstrdup(options.pubkey_algorithms);
	for (p = strsep(&cp, ",");
	     p && *p != '\0';
	     p = strsep(&cp, ",")
	) {
		if (pktype == key_type_from_name(p)) {
#ifdef OPENSSL_HAS_ECC
			if (key_type_plain(pktype) == KEY_ECDSA) {
				if (curve_nid == -1)
				    curve_nid = key_ecdsa_nid_from_name(pkalg);
				if (curve_nid != key_ecdsa_nid_from_name(p))
				    continue;
			}
#endif
			xfree(s);
			return(1);
		}
	}
	xfree(s);
	return(0);
}

static int
key_readx(Key *ret, char **cpp) {
	int flag;

	flag = key_read(ret, cpp);
	if (flag == 1) return(1);

	switch (ret->type) {
	case KEY_X509_RSA:
		debug3("pubkey key_readx(RSA)");
		ret->type = KEY_RSA;
		flag = key_read(ret, cpp);
		break;
	case KEY_X509_DSA:
		debug3("pubkey key_readx(DSA)");
		ret->type = KEY_DSA;
		flag = key_read(ret, cpp);
		break;
	}
	return(flag);
}

static int
key_match(const Key *key, const Key *found) {
	if (key == NULL || found == NULL)
		return(0);

	if (key->type == found->type) {
#ifdef SSH_X509STORE_DISABLED
		return(key_equal(key, found));
#else /*ndef SSH_X509STORE_DISABLED*/
		if (!key_equal(key, found))
			return(0);

		/*
		 * Key are equal but in case of certificates
		 * when x509store is enabled found key may
		 * contain only distinguished name.
		 */
		if ((found->type != KEY_X509_RSA) &&
		    (found->type != KEY_X509_DSA))
			return(1);

		debug3("key_match:found matching certificate");
		if (!ssh_x509flags.key_allow_selfissued) {
			/*
			 * Only the verification process can
			 * allow the received certificate.
			 */
			return(1);
		}

		/*
		 * The public key or certificate found in
		 * autorized keys file can allow self-issued.
		 */
		if (!ssh_is_selfsigned(key->x509))
			return(1);

		debug3("key_match:self-signed certificate");
		ssh_x509flags.key_allow_selfissued = 0;
		if (ssh_x509cert_check(key->x509) == 1) {
			/* the certificated is trusted by x509store */
			ssh_x509flags.key_allow_selfissued = 1;
			return(1);
		}
		ssh_x509flags.key_allow_selfissued = 1;

		/* the certificate can be allowed by public key */
#endif /*ndef SSH_X509STORE_DISABLED*/
	}

	if ((key->type == KEY_X509_RSA) &&
	    ((found->type == KEY_RSA) || (found->type == KEY_X509_RSA))
	) {
		debug3("key_match:RSA");
		return(key->rsa != NULL && found->rsa != NULL &&
		    BN_cmp(key->rsa->e, found->rsa->e) == 0 &&
		    BN_cmp(key->rsa->n, found->rsa->n) == 0);
	}
	if ((key->type == KEY_X509_DSA) &&
	    ((found->type == KEY_DSA) || (found->type == KEY_X509_DSA))
	) {
		debug3("key_match:DSA");
		return(key->dsa != NULL && found->dsa != NULL &&
		    BN_cmp(key->dsa->p, found->dsa->p) == 0 &&
		    BN_cmp(key->dsa->q, found->dsa->q) == 0 &&
		    BN_cmp(key->dsa->g, found->dsa->g) == 0 &&
		    BN_cmp(key->dsa->pub_key, found->dsa->pub_key) == 0);
	}
	return(0);
}

/* return 1 if user allows given key */
static int
user_key_allowed2(struct passwd *pw, Key *key, char *file)
{
	char line[SSH_MAX_PUBKEY_BYTES];
	const char *reason;
	int found_key = 0;
	FILE *f;
	u_long linenum = 0;
	Key *found;
	char *fp;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	f = auth_openkeyfile(file, pw, options.strict_modes);

	if (!f) {
		restore_uid();
		return 0;
	}

	found_key = 0;
	found = key_new(key_is_cert(key) ? KEY_UNSPEC : key->type);

	while (read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
		char *cp, *key_options = NULL;

		auth_clear_options();

		/* Skip leading whitespace, empty and comment lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;

		found->type = key->type;
		if (key_readx(found, &cp) != 1) {
			/* no key?  check if there are options for this key */
			int quoted = 0;
			debug2("user_key_allowed: check options: '%s'", cp);
			key_options = cp;
			for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
				if (*cp == '\\' && cp[1] == '"')
					cp++;	/* Skip both */
				else if (*cp == '"')
					quoted = !quoted;
			}
			/* Skip remaining whitespace. */
			for (; *cp == ' ' || *cp == '\t'; cp++)
				;
			found->type = key_is_cert(key) ? KEY_UNSPEC : key->type;
			if (key_readx(found, &cp) != 1) {
				debug2("user_key_allowed: advance: '%s'", cp);
				/* still no key?  advance to next line*/
				continue;
			}
		}
		if (key_is_cert(key)) {
			if (!key_equal(found, key->cert->signature_key))
				continue;
			if (auth_parse_options(pw, key_options, file,
			    linenum) != 1)
				continue;
			if (!key_is_cert_authority)
				continue;
			fp = key_fingerprint(found, SSH_FP_MD5,
			    SSH_FP_HEX);
			debug("matching CA found: file %s, line %lu, %s %s",
			    file, linenum, key_type(found), fp);
			/*
			 * If the user has specified a list of principals as
			 * a key option, then prefer that list to matching
			 * their username in the certificate principals list.
			 */
			if (authorized_principals != NULL &&
			    !match_principals_option(authorized_principals,
			    key->cert)) {
				reason = "Certificate does not contain an "
				    "authorized principal";
 fail_reason:
				xfree(fp);
				error("%s", reason);
				auth_debug_add("%s", reason);
				continue;
			}
			if (key_cert_check_authority(key, 0, 0,
			    authorized_principals == NULL ? pw->pw_name : NULL,
			    &reason) != 0)
				goto fail_reason;
			if (auth_cert_options(key, pw) != 0) {
				xfree(fp);
				continue;
			}
			verbose("Accepted certificate ID \"%s\" "
			    "signed by %s CA %s via %s", key->cert->key_id,
			    key_type(found), fp, file);
			xfree(fp);
			found_key = 1;
			break;
		} else if (key_match(key, found)) {
			if (auth_parse_options(pw, key_options, file,
			    linenum) != 1)
				continue;
			if (key_is_cert_authority)
				continue;
			found_key = 1;
			debug("matching key found: file %s, line %lu",
			    file, linenum);
			/* Variable key always contain public key or
			 * certificate. In case of X.509 certificate
			 * x509 attribute of Key structure "found"
			 * can contain only "Distinguished Name" !
			 */
			fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
			verbose("Found matching %s key: %s",
			    key_type(found), fp);
			if (key_is_x509(key)) {
				if (ssh_x509cert_check(key->x509) != 1) {
					found_key = 0;
					verbose("x509 certificate check reject matching key");
				}
			}
			xfree(fp);
			break;
		}
	}
	restore_uid();
	fclose(f);
	key_free(found);
	if (!found_key)
		debug2("key not found");
	return found_key;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
static int
user_cert_trusted_ca(struct passwd *pw, Key *key)
{
	char *ca_fp, *principals_file = NULL;
	const char *reason;
	int ret = 0;

	if (!key_is_cert(key) || options.trusted_user_ca_keys == NULL)
		return 0;

	ca_fp = key_fingerprint(key->cert->signature_key,
	    SSH_FP_MD5, SSH_FP_HEX);

	if (key_in_file(key->cert->signature_key,
	    options.trusted_user_ca_keys, 1) != 1) {
		debug2("%s: CA %s %s is not listed in %s", __func__,
		    key_type(key->cert->signature_key), ca_fp,
		    options.trusted_user_ca_keys);
		goto out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	if ((principals_file = authorized_principals_file(pw)) != NULL) {
		if (!match_principals_file(principals_file, pw, key->cert)) {
			reason = "Certificate does not contain an "
			    "authorized principal";
 fail_reason:
			error("%s", reason);
			auth_debug_add("%s", reason);
			goto out;
		}
	}
	if (key_cert_check_authority(key, 0, 1,
	    principals_file == NULL ? pw->pw_name : NULL, &reason) != 0)
		goto fail_reason;
	if (auth_cert_options(key, pw) != 0)
		goto out;

	verbose("Accepted certificate ID \"%s\" signed by %s CA %s via %s",
	    key->cert->key_id, key_type(key->cert->signature_key), ca_fp,
	    options.trusted_user_ca_keys);
	ret = 1;

 out:
	if (principals_file != NULL)
		xfree(principals_file);
	if (ca_fp != NULL)
		xfree(ca_fp);
	return ret;
}

/* check whether given key is in .ssh/authorized_keys* */
int
user_key_allowed(struct passwd *pw, Key *key)
{
	u_int success, i;
	char *file;

	if (auth_key_is_revoked(key))
		return 0;
	if (key_is_cert(key) && auth_key_is_revoked(key->cert->signature_key))
		return 0;

	success = user_cert_trusted_ca(pw, key);
	if (success)
		return success;

	for (i = 0; !success && i < options.num_authkeys_files; i++) {
		file = expand_authorized_keys(
		    options.authorized_keys_files[i], pw);
		success = user_key_allowed2(pw, key, file);
		xfree(file);
	}

	return success;
}

Authmethod method_pubkey = {
	"publickey",
	userauth_pubkey,
	&options.pubkey_authentication
};
