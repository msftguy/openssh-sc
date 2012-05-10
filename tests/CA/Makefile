SHELL=/bin/sh
srcdir=.
SSH_OCSP=yes
#SSH_OCSP=no
RSAKEYBITS=2048


all:


clean: ldap_clean
	-rm -f testhostkey_*
	-rm -f testid_*
	-rm -f selfid_*
	-rm -f testocsp_*
	-rm -fr ca-test/
	-rm -f openssh_ca-?.log*
	-rm -f openssh_ca-3.*.log*
	-rm -f va-*.log
	-rm -f sshd_x509.log

distclean: clean
	-rm -f env
	-rm -f Makefile

# ===

check-certs: ca_files hostkeys identities selfidentities ocsp_certs crl_files ldap_files
	@echo
	$(SHELL) $(srcdir)/openssh_tests.sh

# ===
ca_files: ca-test/catest.config ca-test/catest-bundle.crt

#user is responsible to recreate X.509 tests files !!!
#ca-test/catest.config: $(srcdir)/config
ca-test/catest.config:
	@echo
	SSH_OCSP=$(SSH_OCSP) \
	$(SHELL) $(srcdir)/1-cre_cadb.sh

ca-test/catest-bundle.crt: ca-test/catest.config
	@echo
	$(SHELL) $(srcdir)/2-cre_cakeys.sh

# ===
hostkeys: testhostkey_rsa.certstamp testhostkey_dsa.certstamp

testhostkey_rsa:
	@echo
	@echo "generating RSA 'hostkey'"
	$(SHELL) $(srcdir)/2-cre_key.sh -t rsa -b $(RSAKEYBITS) -f $@ -N ""

testhostkey_rsa.certstamp: testhostkey_rsa ca-test/catest-bundle.crt
	@echo
	@echo "generating RSA server certificates, keys, etc."
	$(SHELL) $(srcdir)/3-cre_certs.sh -f testhostkey_rsa -t server -n "localhost RSA"

testhostkey_dsa:
	@echo
	@echo "generating DSA 'hostkey'"
	$(SHELL) $(srcdir)/2-cre_key.sh -t dsa -f $@ -N ""

testhostkey_dsa.certstamp: testhostkey_dsa ca-test/catest-bundle.crt
	@echo
	@echo "generating DSA server certificates, keys, etc."
	$(SHELL) $(srcdir)/3-cre_certs.sh -f testhostkey_dsa -t server -n "localhost DSA"


# ===
identities: testid_rsa.certstamp testid_dsa.certstamp

testid_rsa:
	@echo
	@echo "generating RSA 'Identity'"
	$(SHELL) $(srcdir)/2-cre_key.sh -t rsa -b $(RSAKEYBITS) -f $@ -N ""

testid_rsa.certstamp: testid_rsa ca-test/catest-bundle.crt
	@echo
	@echo "generating RSA client certificates, keys, etc."
	$(SHELL) $(srcdir)/3-cre_certs.sh -f testid_rsa -t client -n "OpenSSH RSA test certificate"

testid_dsa:
	@echo
	@echo "generating DSA 'Identity'"
	$(SHELL) $(srcdir)/2-cre_key.sh -t dsa -f $@ -N ""

testid_dsa.certstamp: testid_dsa ca-test/catest-bundle.crt
	@echo
	@echo "generating DSA client certificates, keys, etc."
	$(SHELL) $(srcdir)/3-cre_certs.sh -f testid_dsa -t client -n "OpenSSH DSA test certificate"


# ===
selfidentities: selfid_rsa.certstamp selfid_dsa.certstamp

selfid_rsa.certstamp: selfid_rsa
	@echo
	@echo "generating RSA client self-signed certificates, keys, etc."
	$(SHELL) $(srcdir)/3-cre_certs.sh -f selfid_rsa -t self -n "OpenSSH RSA test self-signed certificate"

selfid_rsa:
	@echo
	@echo "generating RSA 'Identity' for self-signed"
	$(SHELL) $(srcdir)/2-cre_key.sh -t rsa -b $(RSAKEYBITS) -f $@ -N ""

selfid_dsa.certstamp: selfid_dsa
	@echo
	@echo "generating DSA client self-signed certificates, keys, etc."
	$(SHELL) $(srcdir)/3-cre_certs.sh -f selfid_dsa -t self -n "OpenSSH DSA test self-signed certificate"

selfid_dsa:
	@echo
	@echo "generating DSA 'Identity' for self-signed"
	$(SHELL) $(srcdir)/2-cre_key.sh -t dsa -f $@ -N ""


# ===
#ocsp_certs:
ocsp_certs: testocsp_rsa.certstamp testocsp_dsa.certstamp

testocsp_rsa.certstamp: testocsp_rsa ca-test/catest-bundle.crt
	@echo; echo "generating RSA ocsp responder certificates."
	SSH_OCSP=$(SSH_OCSP) \
	$(SHELL) $(srcdir)/3-cre_certs.sh -f testocsp_rsa -t ocsp -n "validator RSA"

testocsp_rsa:
	@echo; echo "generating RSA 'ocspkey'"
	$(SHELL) $(srcdir)/2-cre_key.sh -t rsa -b $(RSAKEYBITS) -f $@ -N ""

testocsp_dsa.certstamp: testocsp_dsa ca-test/catest-bundle.crt
	@echo; echo "generating DSA ocsp responder certificates."
	SSH_OCSP=$(SSH_OCSP) \
	$(SHELL) $(srcdir)/3-cre_certs.sh -f testocsp_dsa -t ocsp -n "validator DSA"

testocsp_dsa:
	@echo; echo "generating DSA 'ocspkey'"
	$(SHELL) $(srcdir)/2-cre_key.sh -t dsa -f $@ -N ""


# ===
crl_files: ca-test/catest-bundle.crl

ca-test/catest-bundle.crl: testid_rsa-rsa_sha1 testid_dsa-rsa_sha1
	@echo
	$(SHELL) $(srcdir)/4-cre_crls.sh

# ===
ldap_files:
#ldap_files: ldap/slapd.conf.tmpl

#ldap/slapd.conf.tmpl: env
#	@echo
#	$(SHELL) $(srcdir)/5-cre_ldap.sh

ldap_clean:
#ldap_clean:
#	-rm -f ldap_setup.log
#	-rm -fr ldap
