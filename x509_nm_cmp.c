/*
 * Copyright (c) 2005-2007,2011 Roumen Petrov.  All rights reserved.
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

/* initial code is moved from ssh-x509.c */
#include "includes.h"

#ifndef SSH_X509STORE_DISABLED
#include <ctype.h>
#include <string.h>

#include "x509store.h"
#include "log.h"
#include "xmalloc.h"


static int
ssh_ASN1_OBJECT_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b) {
	int lmin = MIN(a->length, b->length);

	int ret = memcmp(a->data, b->data, lmin);

	return((ret == 0)
		? (b->length - a->length)
		: ret);
}


static int
ssh_ASN1_STRING_casecmp(const ASN1_STRING *a, const ASN1_STRING *b)
{
	int la = M_ASN1_STRING_length(a);
	int lb = M_ASN1_STRING_length(b);
	const char *sa = (const char *)M_ASN1_STRING_data(a);
	const char *sb = (const char *)M_ASN1_STRING_data(b);

	return((strncasecmp(sa, sb, MIN(la, lb)) != 0) ? (lb - la) : 0);
}


/* - from RFC3280 (obsoletes: 2459)
 *   (d) attribute values in PrintableString are compared after
 *   removing leading and trailing white space and converting internal
 *   substrings of one or more consecutive white space characters to a
 *   single space.
 * - from RFC5280 (obsoletes: 3280, 4325, 4630)
 *  Before comparing names using the caseIgnoreMatch matching rule,
 *  conforming implementations MUST perform the six-step string
 *  preparation algorithm described in [RFC4518] for each attribute of
 *  type DirectoryString, with the following clarifications:
 *     *  In step 2, Map, the mapping shall include case folding as
 *        specified in Appendix B.2 of [RFC3454].
 *     *  In step 6, Insignificant Character Removal, perform white space
 *        compression as specified in Section 2.6.1, Insignificant Space
 *        Handling, of [RFC4518].
 * NOTE: In "Section 2.6.1, Insignificant Space Handling, of RFC4518"
 *  space is defined to be the "SPACE (U+0020) code point followed by
 *  no combining marks".
 */
static int
ssh_printable_casecmp(const u_char *pa, int la, const u_char *pb, int lb)
{
/*
 * Be careful: this method work fine only in "C(POSIX)" locale.
 * Since OpenSSH now run without to set locale, i.e.
 * following comparision is OK.
 * This implementation should be changed for other locales !!!
 *
 * Note pa or pb may contain utf8 characters !
 */
	/* skip leading spaces */
	for (; la > 0 && isspace((int)*pa); la--, pa++);
	for (; lb > 0 && isspace((int)*pb); lb--, pb++);

	/* skip trailing spaces */
	{
		const u_char *p;
		for (p = pa + la - 1; la > 0 && isspace((int)*p); la--, p--);
		for (p = pb + lb - 1; lb > 0 && isspace((int)*p); lb--, p--);
	}

	while (la > 0 && lb > 0)
	{
		int chA = tolower((int)*pa);
		int chB = tolower((int)*pb);

		if (chA != chB)
			return(chB - chA);

		pa++; pb++;
		la--; lb--;
		if (isspace(chA)) {
			/* skip inner spaces */
			for (; la > 0 && isspace((int)*pa); la--, pa++);
			for (; lb > 0 && isspace((int)*pb); lb--, pb++);
		}
	}
	return(lb - la);
}


static int
ssh_ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in) {
/*
 * Note before OpenSSL versions 0.7.e method ASN1_STRING_to_UTF8
 * fail when ASN1_STRING is utf8String !
 */
	int tag;
	int l;

	if (!in) return(-1);

	tag = M_ASN1_STRING_type(in);
	if (tag != V_ASN1_UTF8STRING) {
		/*OpenSSL method surprisingly require non-const(!?) ASN1_STRING!*/
		return(ASN1_STRING_to_UTF8(out, in));
	}

	l = M_ASN1_STRING_length(in);
	if (out) {
		u_char *p;

		if (*out) {
			error("ssh_ASN1_STRING_to_UTF8: *out is not NULL");
			return(-1);
		}
		/* we MUST allocate memory with OPENSSL method! */
		p = OPENSSL_malloc(l + 1);
		if (p == NULL) {
			fatal("ssh_ASN1_STRING_to_UTF8: out of memory (allocating %d bytes)", (l + 1));
		}
		memcpy(p, M_ASN1_STRING_data(in), l);
		p[l] = 0;
		*out = p;
	}
	return(l);
}


static int
ssh_ASN1_PRINTABLESTRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b)
{
	int n = -1;
	int tagA, tagB;
	int la, lb;
	u_char *pa, *pb;
	u_char *ua = NULL, *ub = NULL;

	tagA = M_ASN1_STRING_type(a);
	tagB = M_ASN1_STRING_type(b);
	if (tagA != V_ASN1_PRINTABLESTRING) {
		debug3("ssh_ASN1_PRINTABLESTRING_cmp: a->type=%d(%.30s) is not PrintableString", tagA, ASN1_tag2str(tagA));
		/* just in case - see caling methods */
		if (tagB != V_ASN1_PRINTABLESTRING) {
			error("ssh_ASN1_PRINTABLESTRING_cmp: b is not PrintableString too");
			return(-1);
		}
	}
	if (tagB != V_ASN1_PRINTABLESTRING) {
		debug3("ssh_ASN1_PRINTABLESTRING_cmp: b->type=%d(%.30s) is not PrintableString", tagB, ASN1_tag2str(tagB));
		/* just in case - see caling methods */
		if (tagA != V_ASN1_PRINTABLESTRING) {
			error("ssh_ASN1_PRINTABLESTRING_cmp: a is not PrintableString too");
			return(1);
		}
	}

	if (tagA == tagB) {
		/*both are PrintableString*/
		la = M_ASN1_STRING_length(a);
		pa = M_ASN1_STRING_data(a);
		lb = M_ASN1_STRING_length(b);
		pb = M_ASN1_STRING_data(b);
	} else {
		/*convert strings to utf8*/
		la = ssh_ASN1_STRING_to_UTF8(&ua, a);
		if (la <= 0) {
			/*first string is lower in case of error or zero length*/
			n = -1;
			goto done;
		}
		lb = ssh_ASN1_STRING_to_UTF8(&ub, b);
		if (lb <= 0) {
			/*second string is greater in case of error or zero length*/
			n = 1;
			goto done;
		}
		pa = ua;
		pb = ub;
	}

	n = ssh_printable_casecmp(pa, la, pb, lb);

done:
	if(ua) OPENSSL_free(ua);
	if(ub) OPENSSL_free(ub);
#ifdef SSHX509TEST_DBGCMP
fprintf(stderr, "ssh_ASN1_PRINTABLESTRING_cmp: return %d\n", n);
#endif
	return(n);
}


/*
 * =====================================================================
 * from RFC3280 and oldest 2459:
 * DirectoryString ::= CHOICE {
 *        teletexString           TeletexString (SIZE (1..MAX)),
 *        printableString         PrintableString (SIZE (1..MAX)),
 *        universalString         UniversalString (SIZE (1..MAX)),
 *        utf8String              UTF8String (SIZE (1..MAX)),
 *        bmpString               BMPString (SIZE (1..MAX)) }
 *.....
 * The DirectoryString type is defined as a choice of PrintableString,
 * TeletexString, BMPString, UTF8String, and UniversalString.  The
 * UTF8String encoding is the preferred encoding, and all certificates
 * issued after December 31, 2003 MUST use the UTF8String encoding of
 * DirectoryString (except as noted below).  Until that date, conforming
 * CAs MUST choose from the following options when creating a
 * distinguished name, including their own:
 *    (a) if the character set is sufficient, the string MAY be
 *    represented as a PrintableString;
 *    (b) failing (a), if the BMPString character set is sufficient the
 *    string MAY be represented as a BMPString; and
 *    (c) failing (a) and (b), the string MUST be represented as a
 *    UTF8String.  If (a) or (b) is satisfied, the CA MAY still choose
 *    to represent the string as a UTF8String.
 *.....
 * later in RFCs:
 *    (a) attribute values encoded in different types (e.g.,
 *    PrintableString and BMPString) may be assumed to represent
 *    different strings;
 *    (b) attribute values in types other than PrintableString are case
 *    sensitive (this permits matching of attribute values as binary
 *    objects);
 *    (c) attribute values in PrintableString are not case sensitive
 *    (e.g., "Marianne Swanson" is the same as "MARIANNE SWANSON"); and
 *    (d) attribute values in PrintableString are compared after
 *    removing leading and trailing white space and converting internal
 *    substrings of one or more consecutive white space characters to a
 *    single space.
 * =====================================================================
 *
 * OpenSSH implementation:
 * - assume that all DirectoryStrings represent same strings regardless
 * of type. When strings are from different types they will be converted
 * to utf8 before comparison.
 * - when one of the strings is PrintableString they will be compared
 * with method that ignore cases and spaces and convert to utf8
 * if necessary.
 *
 * Note calling method shoud ensure that both strings are
 * DirectoryString !!!
 */
static int
ssh_ASN1_DIRECTORYSTRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b)
{
/* NOTE:
 * - RFC3280 required only binary comparison of attribute values encoded in
 * UTF8String.
 * - RFC5280 conforming implementations for DirectoryString type MUST support
 * name comparisons using caseIgnoreMatch - see Appendix B.2 of RFC3454.
 */
	int n = -1;
	int tagA, tagB;
	int la, lb;
	const char *pa, *pb;
	u_char *ua = NULL, *ub = NULL;

	tagA = M_ASN1_STRING_type(a);
	tagB = M_ASN1_STRING_type(b);

	/* just in case of PrintableString - see caling method ;-) */
	if ((tagA == V_ASN1_PRINTABLESTRING) ||
	    (tagB == V_ASN1_PRINTABLESTRING) ) {
		/*
		 * one is PrintableString and we will compare
		 * according rules for PrintableString.
		 */
		return(ssh_ASN1_PRINTABLESTRING_cmp(a, b));
	}
/*....*/
	if (tagA == tagB) {
		la = M_ASN1_STRING_length(a);
		pa = (const char *)M_ASN1_STRING_data(a);
		lb = M_ASN1_STRING_length(b);
		pb = (const char *)M_ASN1_STRING_data(b);
	} else {
		/*convert both string to utf8*/
		la = ssh_ASN1_STRING_to_UTF8(&ua, a);
		if (la <= 0) {
			/*first string is lower in case of error or zero length*/
			n = -1;
			goto done;
		}
		lb = ssh_ASN1_STRING_to_UTF8(&ub, b);
		if (lb <= 0) {
			/*second string is greater in case of error or zero length*/
			logit("ssh_ASN1_DIRECTORYSTRING_cmp lb=%d", lb);
			n = 1;
			goto done;
		}
#ifdef SSHX509TEST_DBGCMP
fprintf(stderr, "ssh_ASN1_DIRECTORYSTRING_cmp ua='%s'\n", ua);
fprintf(stderr, "ssh_ASN1_DIRECTORYSTRING_cmp ub='%s'\n", ub);
#endif
		pa = (const char *)ua;
		pb = (const char *)ub;
	}

	n = memcmp(pa, pb, (size_t)MIN(la, lb));
#ifdef SSHX509TEST_DBGCMP
fprintf(stderr, "ssh_ASN1_DIRECTORYSTRING_cmp n=%d, la=%d, lb=%d\n", n, la, lb);
#endif
	if (n == 0) n = (lb - la);

done:
	if(ua) OPENSSL_free(ua);
	if(ub) OPENSSL_free(ub);
#ifdef SSHX509TEST_DBGCMP
fprintf(stderr, "ssh_ASN1_DIRECTORYSTRING_cmp: return %d\n", n);
#endif
	return(n);
}


static int/*bool*/
ssh_is_DirectoryString(const ASN1_STRING* s) {
	int tag = M_ASN1_STRING_type(s);

	switch(tag) {
	case V_ASN1_T61STRING: /*==V_ASN1_TELETEXSTRING*/
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_UNIVERSALSTRING:
	case V_ASN1_UTF8STRING:
	case V_ASN1_BMPSTRING:
		return(1);
	default:
		return(0);
	}
}


/*
 * 1.)
 *   Since version 0.9.7.beta4 and 0.9.6h OpenSSL function X509_NAME_cmp
 *   is more restrictive but more correct (!).
 *   Problem is that some x509 implementation set X509_NAME entry
 *   incorrectly to "Printable String" :-[ .
 *   Work around: when one entry is "Printable String" method compare
 *   to corresponding entry as "Printable String".
 * 2.)
 *   OpenSSL functions X509_NAME_cmp check nids order in X509_NAME.
 *   i.e. X509_NAME{"/C=XX/O=YY"} is not equal to X509_NAME{"/O=YY/C=XX"}
 */
int
ssh_X509_NAME_cmp(X509_NAME *_a, X509_NAME *_b) {
	int k, n;
	X509_NAME *b;

#if 1
	/*XXX: to call fatal when _a or _b is NULL or to use next*/
	if (_a == NULL) {
		return((_b == NULL) ? 0 : 1);
	} else {
		if (_b == NULL) return(-1);
	}
#else
	if (_a == NULL) {
		fatal("ssh_X509_NAME_cmp: first name is NULL");
	}
	if (_b == NULL) {
		fatal("ssh_X509_NAME_cmp: second name is NULL");
	}
#endif

	k = sk_X509_NAME_ENTRY_num(_a->entries);
	n = sk_X509_NAME_ENTRY_num(_b->entries);

	if (k != n)
		return(n - k);

	b = X509_NAME_dup(_b);
	n = 0;
	for (--k; k >= 0; k--) {
		X509_NAME_ENTRY *neA;
		ASN1_STRING     *nvA;
		int nid;
		X509_NAME_ENTRY *neB;
		ASN1_STRING     *nvB;
		int              loc;

		neA = sk_X509_NAME_ENTRY_value(_a->entries, k);
		nvA = neA->value;
		nid = OBJ_obj2nid(neA->object);
		loc = X509_NAME_get_index_by_NID(b, nid, -1);
		if (loc < 0) {
			char *buf1, *buf2;

			buf1 = ssh_X509_NAME_oneline(_a); /*fatal on error*/
			buf2 = ssh_X509_NAME_oneline(_b); /*fatal on error*/
			debug3("ssh_X509_NAME_cmp: insufficient entries with nid=%d(%.40s) in second name."
				" na=%s, nb=%s",
				nid, OBJ_nid2ln(nid),
				buf1, buf2);
			xfree(buf1);
			xfree(buf2);
			n = -1;
			break;
		}
trynextentry:
		neB = sk_X509_NAME_ENTRY_value(b->entries, loc);
		nvB = neB->value;
#ifdef SSHX509TEST_DBGCMP
{
	int l, tag;

	l   = M_ASN1_STRING_length(nvA);
	tag = M_ASN1_STRING_type  (nvA);
	fprintf(stderr, "nvA(%.40s:%d)='", ASN1_tag2str(tag), l);
	ASN1_STRING_print_ex_fp(stderr, nvA, /*flags*/0);
	fputs("'\n", stderr);

	l   = M_ASN1_STRING_length(nvB);
	tag = M_ASN1_STRING_type  (nvB);
	fprintf(stderr, "nvA(%.40s:%d)='", ASN1_tag2str(tag), l);
	ASN1_STRING_print_ex_fp(stderr, nvB, /*flags*/0);
	fputs("'\n", stderr);
}
#endif

		if (nid == NID_pkcs9_emailAddress) {
			int tag;

			tag = M_ASN1_STRING_type(nvA);
			if (tag != V_ASN1_IA5STRING) {
				/* to be strict and return nonzero or ... ? XXX
				n = -1;
				break;
				*/
				error("ssh_X509_NAME_cmp: incorrect type for emailAddress(a) %d(%.30s)", tag, ASN1_tag2str(tag));
			}

			tag = M_ASN1_STRING_type(nvB);
			if (tag != V_ASN1_IA5STRING) {
				/* to be strict and return nonzero or ... ? XXX
				n = 1;
				break;
				*/
				error("ssh_X509_NAME_cmp: incorrect type for emailAddress(b) %d(%.30s)", tag, ASN1_tag2str(tag));
			}

			n = ssh_ASN1_STRING_casecmp(nvA, nvB);
			if (n == 0) goto entryisok;

			goto getnextentry;
		}
		if ((M_ASN1_STRING_type(nvA) == V_ASN1_PRINTABLESTRING) ||
		    (M_ASN1_STRING_type(nvB) == V_ASN1_PRINTABLESTRING) ) {
			n = ssh_ASN1_PRINTABLESTRING_cmp(nvA, nvB);
			if (n == 0) goto entryisok;

			goto getnextentry;
		}
		if (ssh_is_DirectoryString(nvA) &&
		    ssh_is_DirectoryString(nvB)) {
			n = ssh_ASN1_DIRECTORYSTRING_cmp(nvA, nvB);
			if (n == 0) goto entryisok;

			goto getnextentry;
		}

		n = M_ASN1_STRING_length(nvA) - M_ASN1_STRING_length(nvB);
		if (n != 0) goto getnextentry;

		n = M_ASN1_STRING_length(nvA);
		n = memcmp(nvA->data, nvB->data, n);
		if (n != 0) goto getnextentry;

		/* openssl check object too */
		n = ssh_ASN1_OBJECT_cmp(neA->object, neB->object);
		if (n != 0) goto getnextentry;

entryisok:
		{
			X509_NAME_ENTRY *ne = X509_NAME_delete_entry(b, loc);
			X509_NAME_ENTRY_free(ne);
		}
		continue;
getnextentry:
		loc = X509_NAME_get_index_by_NID(b, nid, loc);
		if (loc < 0) {
			break;
		}
		goto trynextentry;
	}

	X509_NAME_free(b);
#ifdef SSHX509TEST_DBGCMP
fprintf(stderr, "ssh_X509_NAME_cmp: return %d\n", n);
#endif
	return(n);
}
#endif /*ndef SSH_X509STORE_DISABLED*/
