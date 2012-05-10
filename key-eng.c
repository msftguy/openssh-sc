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

#ifdef USE_OPENSSL_ENGINE
#include <string.h>
#include <openssl/ui.h>

#include "key.h"
#include "key-eng.h"
#include "log.h"
#include "xmalloc.h"
#include "misc.h"

#define USE_SSH_UI_PROMPT


typedef struct ssh_pw_cb_data {
	const void *password;
} SSH_PW_CB_DATA;


static UI_METHOD *ssh_ui_method = NULL;

/**/
static int
ui_open(UI *ui) {
	return(UI_method_get_opener(UI_OpenSSL())(ui));
}


static int
ui_read(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					UI_set_result(ui, uis, password);
					return(1);
				}
				} break;
			default:
				break;
			}
		}
	}

#ifdef USE_SSH_UI_PROMPT
{ /* use own method to prompt properly */
	int flags = RP_USE_ASKPASS | RP_ALLOW_STDIN;
	if (ui_flags & UI_INPUT_FLAG_ECHO)
		flags |= RP_ECHO;

	switch(uis_type) {
	case UIT_PROMPT:
	case UIT_VERIFY: {
		const char *prompt;
		char *password;

		prompt = UI_get0_output_string(uis);
		debug3("%s: read_passphrase prompt=%s", __func__, prompt);
		password = read_passphrase(prompt, flags);
		UI_set_result(ui, uis, password);
		memset(password, 'x', strlen(password));
		xfree(password);
		return(1);
		} break;
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		verbose("%s: UIT_INFO '%s'", __func__, s);
		return(1);
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error("%s: UIT_ERROR '%s'", __func__, s);
		return(1);
		} break;
	default:
		break;
	}
}

	return(UI_method_get_reader(UI_OpenSSL())(ui, uis));
#else
	return(0);
#endif
}


static int
ui_write(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					return(1);
				}
				} break;
			default:
				break;
			}
		}
	}
	switch(uis_type) {
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		verbose("%s: UIT_INFO '%s'", __func__, s);
		return(1);
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error("%s: UIT_ERROR '%s'", __func__, s);
		return(1);
		} break;
	default:
		break;
	}
	return(UI_method_get_writer(UI_OpenSSL())(ui, uis));
}


static int
ui_close(UI *ui) {
	return(UI_method_get_closer(UI_OpenSSL())(ui));
}


static void destroy_ssh_ui_method(void);


int/*bool*/
setup_ssh_ui_method() {
	ssh_ui_method = UI_create_method((char*)"OpenSSH application user interface");

	if (ssh_ui_method == NULL) return(0);

	if ((UI_method_set_opener(ssh_ui_method, ui_open ) < 0)
	||  (UI_method_set_reader(ssh_ui_method, ui_read ) < 0)
	||  (UI_method_set_writer(ssh_ui_method, ui_write) < 0)
	||  (UI_method_set_closer(ssh_ui_method, ui_close) < 0)) {
		destroy_ssh_ui_method();
		return(0);
	}
	return(1);
}


static void
destroy_ssh_ui_method() {
	if (ssh_ui_method == NULL) return;

	UI_destroy_method(ssh_ui_method);
	ssh_ui_method = NULL;
}


static void
eng_try_load_cert(ENGINE *e, const char *keyid, EVP_PKEY *pk, Key *k) {
	X509*	x509 = NULL;
	int ctrl_ret = 0;

	if (e == NULL)
		return;

	/* try to load certificate wth with LOAD_CERT_EVP command */
	{
		struct {
			EVP_PKEY *pkey;
			X509 *x509;
		} param = {NULL, NULL};
		param.pkey = pk;

		ctrl_ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_EVP", 0, &param, 0, 0);
		debug3("%s: eng cmd LOAD_CERT_EVP return %d", __func__, ctrl_ret);
		if (ctrl_ret == 1)
			x509 = param.x509;
	}

	/* try to load certificate wth with LOAD_CERT_CTRL command */
	if (ctrl_ret != 1) {
		struct {
			const char *keyid;
			X509 *x509;
		} param = {NULL, NULL};
		param.keyid = keyid;

		ctrl_ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &param, 0, 0);
		debug3("%s: eng cmd LOAD_CERT_CTRL return %d", __func__, ctrl_ret);
		if (ctrl_ret == 1)
			x509 = param.x509;
	}
	debug3("%s: eng certificate=%p", __func__, (void*)x509);

	if (x509 == NULL)
		return;

	switch(k->type) {
	case KEY_RSA: k->type = KEY_X509_RSA; k->x509 = x509; break;
	case KEY_DSA: k->type = KEY_X509_DSA; k->x509 = x509; break;
	default: X509_free(x509); break;
	}
}


static ENGINE*
split_eng_keyid(const char *endkeyid, char **engkeyid) {
	ENGINE* e = NULL;
	char *p, *q;

	q = xstrdup(endkeyid);	/*fatal on error*/

	p = strchr(q, ':');
	if (p == NULL) {
		fatal("%s missing engine identifier", __func__);
		goto done; /*;-)*/
	}
	*p = '\0';
	p++;
	if (*p == '\0') {
		fatal("%s missing key identifier", __func__);
		goto done; /*;-)*/
	}

	e = ENGINE_by_id(q);
	if (e != NULL) {
		*engkeyid = xstrdup(p);
	}
done:
	xfree(q);
	return(e);
}


Key*
eng_key_load_private_type(int type, const char *keyid,
	const char *passphrase, char **commentp
) {
	char *engkeyid;
	const char *name = "<no key>";
	ENGINE *e = NULL;
	EVP_PKEY *pk = NULL;
	Key *prv = NULL;
#ifndef USE_SSH_UI_PROMPT
	SSH_PW_CB_DATA cb_data = { NULL };
#endif

	e = split_eng_keyid(keyid, &engkeyid);
	if (e == NULL)
		goto done;

#ifdef USE_SSH_UI_PROMPT
	(void)passphrase;
	pk = ENGINE_load_private_key(e, engkeyid, ssh_ui_method, NULL);
#else
	cb_data.password = passphrase;
	pk = ENGINE_load_private_key(e, engkeyid, ssh_ui_method, &cb_data);
#endif
	if (pk == NULL) {
		char ebuf[512];
		error("%s: ENGINE_load_private_key(%s) fail with errormsg='%.*s'"
		, __func__, ENGINE_get_id(e)
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto done;
	}

	/* NOTE do not set flags |= KEY_FLAG_EXT !!! */

	if (pk->type == EVP_PKEY_RSA
	&&  (type == KEY_UNSPEC || type == KEY_RSA)) {
		prv = key_new(KEY_UNSPEC);
		prv->rsa = EVP_PKEY_get1_RSA(pk);
		prv->type = KEY_RSA;
		name = "rsa(nss)";
#ifdef DEBUG_PK
		RSA_print_fp(stderr, prv->rsa, 8);
#endif
		if (RSA_blinding_on(prv->rsa, NULL) != 1) {
			error("%s: RSA_blinding_on failed", __func__);
			key_free(prv);
			prv = NULL;
		}
	} else if (pk->type == EVP_PKEY_DSA
	&&  (type == KEY_UNSPEC || type == KEY_DSA)) {
		prv = key_new(KEY_UNSPEC);
		prv->dsa = EVP_PKEY_get1_DSA(pk);
		prv->type = KEY_DSA;
		name = "dsa(nss)";
#ifdef DEBUG_PK
		DSA_print_fp(stderr, prv->dsa, 8);
#endif
	} else {
		error("%s: mismatch or "
		    "unknown EVP_PKEY save_type %d", __func__, pk->save_type);
	}

	if ((pk != NULL) && (prv != NULL))
		eng_try_load_cert(e, engkeyid, pk, prv);

	if (pk != NULL)
		EVP_PKEY_free(pk);

	if (prv != NULL && commentp)
		*commentp = xstrdup(name);

done:
	if (e != NULL)
		ENGINE_free(e);
	debug("read ENGINE private key done: type %s", (prv ? key_type(prv) : "<not found>"));
	return(prv);
}


int
eng_key_try_load_public(Key *k, const char *filename, char **commentp) {
	int ret = 0;
	const char *name = "<no key>";
	char *keyid = NULL;
	char *engkeyid;
	ENGINE *e = NULL;
	EVP_PKEY *pk = NULL;
#ifndef USE_SSH_UI_PROMPT
	SSH_PW_CB_DATA cb_data = { NULL };
#endif
	if (k->type != KEY_UNSPEC && k->type != KEY_RSA ) return(-1);

	debug3("%s filename=%s", __func__, filename);
{ /* magic to ignore suffixes in file name*/
	size_t len = strlen(filename);
	if (len <= 4)
		goto done;

	{ /* skip bogus certificates "-cert" */
		const char sfx[5] = "-cert";
		if (len >= sizeof(sfx)) {
			const char *s = filename + len - sizeof(sfx);
			if (strncmp(s, sfx, sizeof(sfx)) == 0)
				return(0);
		}
	}
	{ /* skip bogus certificates "-cert.pub" */
		const char sfx[9] = "-cert.pub";
		if (len >= sizeof(sfx)) {
			const char *s = filename + len - sizeof(sfx);
			if (strncmp(s, sfx, sizeof(sfx)) == 0)
				return(0);
		}
	}

	keyid = xstrdup(filename); /*fatal on error*/
	{ /* drop suffix ".pub" on copy */
		char *s = keyid + len - 4;
		if (strncmp(s, ".pub", 4) == 0)
			*s = '\0';
	}
}
	debug3("%s keyid=%s", __func__, keyid);

	e = split_eng_keyid(keyid, &engkeyid);
	if (e == NULL)
		goto done;

#ifdef USE_SSH_UI_PROMPT
	pk = ENGINE_load_public_key(e, engkeyid, ssh_ui_method, NULL);
#else
	pk = ENGINE_load_public_key(e, engkeyid, ssh_ui_method, &cb_data);
#endif

	if (pk == NULL) {
		char ebuf[512];
		/* fatal here to avoid PIN lock,for instance
		 * when ssh-askpass program is missing.
		 * NOTE OpenSSH try many times to load public key.
		 */
		fatal("%s: ENGINE_load_public_key(%s) fail with errormsg='%.*s'"
		, __func__, ENGINE_get_id(e)
		, (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		goto done;
	}

	/* NOTE do not set flags |= KEY_FLAG_EXT !!! */
	if (pk->type == EVP_PKEY_RSA) {
		k->rsa = EVP_PKEY_get1_RSA(pk);
		k->type = KEY_RSA;
		name = "rsa(nss)";
#ifdef DEBUG_PK
		RSA_print_fp(stderr, k->rsa, 8);
#endif
		if (RSA_blinding_on(k->rsa, NULL) == 1) {
			ret = 1;
		}
		else {
			error("%s: RSA_blinding_on failed", __func__);
		}
	} else if (pk->type == EVP_PKEY_DSA) {
		k->dsa = EVP_PKEY_get1_DSA(pk);
		k->type = KEY_DSA;
		name = "dsa(nss)";
#ifdef DEBUG_PK
		DSA_print_fp(stderr, k->dsa, 8);
#endif
		ret = 1;
	} else {
		error("%s: mismatch or "
		    "unknown EVP_PKEY save_type %d", __func__, pk->save_type);
	}

	if (ret && (pk != NULL))
		eng_try_load_cert(e, engkeyid, pk, k);

	if (pk != NULL)
		EVP_PKEY_free(pk);

	if (k != NULL && commentp)
		*commentp = xstrdup(engkeyid);

	if (ret)
		debug("read ENGINE public key done: type %s", k ? key_type(k) : "<unknown>");

done:
	if (keyid != NULL)
		xfree(keyid);
	if (e != NULL)
		ENGINE_free(e);
	return(ret);
}


#if 0
void
ssh_load_engines() {
#if 0
	ENGINE_load_builtin_engines();
#else
/* NOTE: We need only dynamic but OPENSSL_cpuid_setup is not designed
 * to be public. Let do not call it for now ;). If is required code
 * will be switched to load all.
 */
#if 0
	OPENSSL_cpuid_setup();
#endif
	ENGINE_load_dynamic();
	ENGINE_register_all_complete();
#endif
	setup_ssh_ui_method();
}
#endif


#if 0
#  define TRY_TO_LOAD_SHARED_ENGINE_LIBRARY
#endif
#ifdef TRY_TO_LOAD_SHARED_ENGINE_LIBRARY
static ENGINE*
try_load_engine(const char *engine) {
	ENGINE *e = ENGINE_by_id("dynamic");

	if (e == NULL)
		goto done;

	if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
	||  !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)
	) {
		ENGINE_free(e);
		e = NULL;
	}
#if 0
???
	if (!ENGINE_add(e)) {
		ENGINE_free(e);
		return(NULL);
	}
#endif

done:
	return(e);
}
#endif /*def TRY_TO_LOAD_SHARED_ENGINE_LIBRARY*/


static ENGINE*
ssh_setup_engine(const char *engine) {
	int ctrl_ret;
	ENGINE *e = NULL;

	if (engine == NULL) {
		fatal("%s: engine is NULL", __func__);
		return(NULL); /* ;-) */
	}

	e = ENGINE_by_id(engine);

#ifdef TRY_TO_LOAD_SHARED_ENGINE_LIBRARY
	if (e == NULL)
        	e = try_load_engine(engine);
#endif

	if (e == NULL) {
		char ebuf[512];
		fatal("%s(%s): setup fail with last error '%.*s'"
		    , __func__, engine
		    , (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		return(NULL); /* ;-) */
	}

	debug3("%s: engine '%s' loaded", __func__, ENGINE_get_name(e));
	if (!ENGINE_init(e)) {
		char ebuf[512];
		fatal("%s(%s): ENGINE_init fail with last error '%.*s'"
		    , __func__, engine
		    , (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
		return(NULL); /* ;-) */
	}

	ctrl_ret = ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ssh_ui_method, 0, 1);
	if (!ctrl_ret) {
		char ebuf[512];
		debug3("%s(%s): unsupported engine command SET_USER_INTERFACE: %.*s"
		    , __func__, engine
		    , (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
	}

	if (!ENGINE_free(e)) {
		e = NULL;
	}
	return(e);
}


#define WHITESPACE " \t\r\n"
/* name of currect engine to process */
static char *eng_name = NULL;

int/*bool*/
process_engconfig_line(char *line, const char *filename, int linenum) {
	int ret = 1;
	size_t len;
	char *s, *keyword, *arg;
	ENGINE *e;
	int ctrl_ret;

	/* strip trailing whitespace */
	len = strlen(line);
	s = line + len - 1;
	for (; len > 0; s--, len--) {
		int ch = (unsigned char)*s;
		if (strchr(WHITESPACE, ch) == NULL)
			break;
		*s = '\0';
	}

	/* ignore leading whitespace */
	s = line;
	if (*s == '\0')
		return(1);
	keyword = strdelim(&s);
	if (keyword == NULL)
		return(1);
	if (*keyword == '\0')
		keyword = strdelim(&s);
	if (keyword == NULL)
		return(1);

	/* ignore comments */
	if (*keyword == '#')
		return(1);

	if (strcasecmp(keyword, "engine") == 0) {
		arg = strdelim(&s);
		if (!arg || *arg == '\0') {
			fatal("%.200s line %d: missing engine identifier"
			    , filename, linenum);
			goto done;
		}

		e = ssh_setup_engine(arg);
		if (e == NULL) {
			char ebuf[512];
			fatal("%.200s line %d: cannot load engine '%s':%.*s"
			    , filename, linenum, arg
			    , (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf)));
			;
		}
		if (eng_name != NULL)
			xfree(eng_name);
		eng_name = xstrdup(arg); /*fatal on error*/

		ENGINE_free(e);
	}
	else {
		if (eng_name == NULL)
			fatal("%.200s line %d: engine is not specified"
			    , filename, linenum);

		e = ENGINE_by_id(eng_name);
		if (e == NULL)
			fatal("%.200s line %d: engine(%s) not found"
			    , filename, linenum, eng_name);

		arg = strdelim(&s);

		ctrl_ret = ENGINE_ctrl_cmd_string(e, keyword, arg, 0);
		if (!ctrl_ret) {
			char ebuf[512];
			fatal("%.200s line %d: engine command fail"
			    " with errormsg='%.*s'"
			    , filename, linenum
			    , (int)sizeof(ebuf), openssl_errormsg(ebuf, sizeof(ebuf))
			);
			ret = 0;
		}

		ENGINE_free(e);
	}

done:
	/* check that there is no garbage at end of line */
	if ((arg = strdelim(&s)) != NULL && *arg != '\0') {
		fatal("%.200s line %d: garbage at end of line - '%.200s'.",
		    filename, linenum, arg);
	}

	return(ret);
}
#endif /*def USE_OPENSSL_ENGINE*/
