#ifndef SSH_XKALG_H
#define SSH_XKALG_H
/*
 * Copyright (c) 2005 Roumen Petrov.  All rights reserved.
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
#include "buffer.h"


typedef struct {
	int           type;
	const char   *name;
	struct {
	const char   *name;
	const EVP_MD *evp;
	}             dgst;
	const char   *signame;
}	SSHX509KeyAlgs;
#define X509PUBALG_SIGNAME(p)	(p->signame ? p->signame : p->name)


void	fill_default_xkalg(void);
	/* format "name,dgst_name[,sig_name]" */
int	ssh_add_x509key_alg(const char *data);


int/*bool*/	ssh_is_x509signame(const char *signame);

int	ssh_xkalg_nameind(const char *name, SSHX509KeyAlgs **q, int loc);
int	ssh_xkalg_typeind(int type, SSHX509KeyAlgs **q, int loc);

void	ssh_list_xkalg(int type, Buffer *b);


#endif /* SSH_XKALG_H */
