# $Id$

# uncomment if you run a non bourne compatable shell. Ie. csh
#SHELL = /bin/sh

AUTORECONF=autoreconf

prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libexecdir=${exec_prefix}/libexec
datadir=${datarootdir}
datarootdir=${prefix}/share
mandir=${datarootdir}/man
mansubdir=man
sysconfdir=${prefix}/etc
sshcadir=/usr/local/etc/ca
piddir=/var/run
srcdir=.
top_srcdir=.

DESTDIR=

SSH_PROGRAM=${exec_prefix}/bin/ssh
ASKPASS_PROGRAM=$(libexecdir)/ssh-askpass
SFTP_SERVER=$(libexecdir)/sftp-server
SSH_KEYSIGN=$(libexecdir)/ssh-keysign
SSH_PKCS11_HELPER=$(libexecdir)/ssh-pkcs11-helper
PRIVSEP_PATH=/var/empty
SSH_PRIVSEP_USER=sshd
STRIP_OPT=-s

PATHS= -DSSHDIR=\"$(sysconfdir)\" \
	-DSSHCADIR=\"$(sshcadir)\" \
	-D_PATH_SSH_PROGRAM=\"$(SSH_PROGRAM)\" \
	-D_PATH_SSH_ASKPASS_DEFAULT=\"$(ASKPASS_PROGRAM)\" \
	-D_PATH_SFTP_SERVER=\"$(SFTP_SERVER)\" \
	-D_PATH_SSH_KEY_SIGN=\"$(SSH_KEYSIGN)\" \
	-D_PATH_SSH_PKCS11_HELPER=\"$(SSH_PKCS11_HELPER)\" \
	-D_PATH_SSH_PIDDIR=\"$(piddir)\" \
	-D_PATH_PRIVSEP_CHROOT_DIR=\"$(PRIVSEP_PATH)\" \

FIPSLD_CC=
CC=gcc
LD=gcc
CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -fno-builtin-memset -fstack-protector-all 
CPPFLAGS=-I. -I$(srcdir)   $(PATHS) -DHAVE_CONFIG_H
LIBS=-lssl -lcrypto -lz  -lresolv
SSHLIBS=
SSHDLIBS=
LIBEDIT=
LIBLDAP= 
AR=/opt/local/bin/ar
AWK=gawk
RANLIB=ranlib
INSTALL=/opt/local/bin/ginstall -c
PERL=/opt/local/bin/perl5
SED=/usr/bin/sed
ENT=
XAUTH_PATH=/opt/local/bin/xauth
LDFLAGS=-L. -Lopenbsd-compat/  -fstack-protector-all
EXEEXT=
MANFMT=/usr/bin/nroff -mandoc

#LDAP_OBJS=x509_by_ldap.o
LDAP_OBJS=

OCSP_OBJS=ssh-ocsp.o
#OCSP_OBJS=

SSHX509_OBJS=ssh-x509.o ssh-xkalg.o x509_nm_cmp.o key-eng.o
X509STORE_OBJS=x509store.o $(LDAP_OBJS) $(OCSP_OBJS)

TARGETS=ssh$(EXEEXT) sshd$(EXEEXT) ssh-add$(EXEEXT) ssh-keygen$(EXEEXT) ssh-keyscan${EXEEXT} ssh-keysign${EXEEXT} ssh-pkcs11-helper$(EXEEXT) ssh-agent$(EXEEXT) scp$(EXEEXT) sftp-server$(EXEEXT) sftp$(EXEEXT)

LIBSSH_OBJS=acss.o authfd.o authfile.o bufaux.o bufbn.o buffer.o \
	canohost.o channels.o cipher.o cipher-acss.o cipher-aes.o \
	cipher-bf1.o cipher-ctr.o cipher-3des1.o cleanup.o \
	compat.o compress.o crc32.o deattack.o fatal.o hostfile.o \
	log.o match.o md-sha256.o moduli.o nchan.o packet.o \
	readpass.o rsa.o ttymodes.o xmalloc.o addrmatch.o \
	atomicio.o key.o dispatch.o kex.o mac.o uidswap.o uuencode.o misc.o \
	monitor_fdpass.o rijndael.o ssh-dss.o ssh-ecdsa.o ssh-rsa.o $(SSHX509_OBJS) dh.o \
	kexdh.o kexgex.o kexdhc.o kexgexc.o bufec.o kexecdh.o kexecdhc.o \
	msg.o progressmeter.o dns.o entropy.o gss-genr.o umac.o jpake.o \
	schnorr.o ssh-pkcs11.o

SSHOBJS= ssh.o readconf.o clientloop.o sshtty.o \
	sshconnect.o sshconnect1.o sshconnect2.o $(X509STORE_OBJS) mux.o \
	roaming_common.o roaming_client.o

SSHDOBJS=sshd.o auth-rhosts.o auth-passwd.o auth-rsa.o auth-rh-rsa.o \
	audit.o audit-bsm.o audit-linux.o platform.o \
	sshpty.o sshlogin.o servconf.o serverloop.o \
	auth.o auth1.o auth2.o auth-options.o session.o \
	auth-chall.o auth2-chall.o groupaccess.o \
	auth-skey.o auth-bsdauth.o auth2-hostbased.o auth2-kbdint.o \
	auth2-none.o auth2-passwd.o auth2-pubkey.o auth2-jpake.o \
	monitor_mm.o monitor.o monitor_wrap.o kexdhs.o kexgexs.o kexecdhs.o \
	auth-krb5.o \
	auth2-gss.o gss-serv.o gss-serv-krb5.o \
	loginrec.o auth-pam.o auth-shadow.o auth-sia.o md5crypt.o \
	sftp-server.o sftp-common.o \
	roaming_common.o roaming_serv.o $(X509STORE_OBJS) \
	sandbox-null.o sandbox-rlimit.o sandbox-systrace.o sandbox-darwin.o \
	sandbox-seccomp-filter.o

MANPAGES	= moduli.5.out scp.1.out ssh-add.1.out ssh-agent.1.out ssh-keygen.1.out ssh-keyscan.1.out ssh.1.out sshd.8.out sftp-server.8.out sftp.1.out ssh-keysign.8.out ssh-pkcs11-helper.8.out sshd_config.5.out ssh_config.5.out ssh_engine.5.out
MANPAGES_IN	= moduli.5 scp.1 ssh-add.1 ssh-agent.1 ssh-keygen.1 ssh-keyscan.1 ssh.1 sshd.8 sftp-server.8 sftp.1 ssh-keysign.8 ssh-pkcs11-helper.8 sshd_config.5 ssh_config.5 ssh_engine.5
MANTYPE		= doc

CONFIGFILES=sshd_config.out ssh_config.out moduli.out
CONFIGFILES_IN=sshd_config ssh_config moduli

PATHSUBS	= \
	-e 's|/etc/ssh/ssh_config|$(sysconfdir)/ssh_config|g' \
	-e 's|/etc/ssh/ssh_known_hosts|$(sysconfdir)/ssh_known_hosts|g' \
	-e 's|/etc/ssh/sshd_config|$(sysconfdir)/sshd_config|g' \
	-e 's|/usr/libexec|$(libexecdir)|g' \
	-e 's|/etc/shosts.equiv|$(sysconfdir)/shosts.equiv|g' \
	-e 's|/etc/ssh/ssh_host_key|$(sysconfdir)/ssh_host_key|g' \
	-e 's|/etc/ssh/ssh_host_ecdsa_key|$(sysconfdir)/ssh_host_ecdsa_key|g' \
	-e 's|/etc/ssh/ssh_host_dsa_key|$(sysconfdir)/ssh_host_dsa_key|g' \
	-e 's|/etc/ssh/ssh_host_rsa_key|$(sysconfdir)/ssh_host_rsa_key|g' \
	-e 's|/etc/ssh/ca/ca-bundle.crt|$(sshcadir)/ca-bundle.crt|g' \
	-e 's|/etc/ssh/ca/crt|$(sshcadir)/crt|g' \
	-e 's|/etc/ssh/ca/ca-bundle.crl|$(sshcadir)/ca-bundle.crl|g' \
	-e 's|/etc/ssh/ca/crl|$(sshcadir)/crl|g' \
	-e 's|/var/run/sshd.pid|$(piddir)/sshd.pid|g' \
	-e 's|/etc/moduli|$(sysconfdir)/moduli|g' \
	-e 's|/etc/ssh/moduli|$(sysconfdir)/moduli|g' \
	-e 's|/etc/ssh/sshrc|$(sysconfdir)/sshrc|g' \
	-e 's|/usr/X11R6/bin/xauth|$(XAUTH_PATH)|g' \
	-e 's|/var/empty|$(PRIVSEP_PATH)|g' \
	-e 's|/usr/bin:/bin:/usr/sbin:/sbin|/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin|g'

FIXPATHSCMD	= $(SED) $(PATHSUBS)

all: $(CONFIGFILES) $(MANPAGES) $(TARGETS)

$(LIBSSH_OBJS): Makefile.in config.h
$(SSHOBJS): Makefile.in config.h
$(SSHDOBJS): Makefile.in config.h

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

LIBCOMPAT=openbsd-compat/libopenbsd-compat.a
$(LIBCOMPAT): always
	(cd openbsd-compat && $(MAKE))
always:

libssh.a: $(LIBSSH_OBJS)
	$(AR) rv $@ $(LIBSSH_OBJS)
	$(RANLIB) $@

ssh$(EXEEXT): $(LIBCOMPAT) libssh.a $(SSHOBJS)
	$(LD) -o $@ $(SSHOBJS) $(LDFLAGS) -lssh -lopenbsd-compat $(LIBLDAP) $(SSHLIBS) $(LIBS)

sshd$(EXEEXT): libssh.a	$(LIBCOMPAT) $(SSHDOBJS)
	$(LD) -o $@ $(SSHDOBJS) $(LDFLAGS) -lssh -lopenbsd-compat $(LIBLDAP) $(SSHDLIBS) $(LIBS)

scp$(EXEEXT): $(LIBCOMPAT) libssh.a scp.o progressmeter.o
	$(LD) -o $@ scp.o progressmeter.o bufaux.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBS)

ssh-add$(EXEEXT): $(LIBCOMPAT) libssh.a ssh-add.o
	$(LD) -o $@ ssh-add.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBS)

ssh-agent$(EXEEXT): $(LIBCOMPAT) libssh.a ssh-agent.o ssh-pkcs11-client.o
	$(LD) -o $@ ssh-agent.o ssh-pkcs11-client.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBS)

ssh-keygen$(EXEEXT): $(LIBCOMPAT) libssh.a ssh-keygen.o
	$(LD) -o $@ ssh-keygen.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBS)

ssh-keysign$(EXEEXT): $(LIBCOMPAT) libssh.a ssh-keysign.o readconf.o $(X509STORE_OBJS) roaming_dummy.o
	$(LD) -o $@ ssh-keysign.o readconf.o $(X509STORE_OBJS) roaming_dummy.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBLDAP) $(LIBS)

ssh-pkcs11-helper$(EXEEXT): $(LIBCOMPAT) libssh.a ssh-pkcs11-helper.o ssh-pkcs11.o
	$(LD) -o $@ ssh-pkcs11-helper.o ssh-pkcs11.o $(LDFLAGS) -lssh -lopenbsd-compat -lssh -lopenbsd-compat $(LIBS)

ssh-keyscan$(EXEEXT): $(LIBCOMPAT) libssh.a ssh-keyscan.o roaming_dummy.o
	$(LD) -o $@ ssh-keyscan.o roaming_dummy.o $(LDFLAGS) -lssh -lopenbsd-compat -lssh $(LIBS)

sftp-server$(EXEEXT): $(LIBCOMPAT) libssh.a sftp.o sftp-common.o sftp-server.o sftp-server-main.o
	$(LD) -o $@ sftp-server.o sftp-common.o sftp-server-main.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBS)

sftp$(EXEEXT): $(LIBCOMPAT) libssh.a sftp.o sftp-client.o sftp-common.o sftp-glob.o progressmeter.o
	$(LD) -o $@ progressmeter.o sftp.o sftp-client.o sftp-common.o sftp-glob.o $(LDFLAGS) -lssh -lopenbsd-compat $(LIBS) $(LIBEDIT)

# test driver for the loginrec code - not built by default
logintest: logintest.o $(LIBCOMPAT) libssh.a loginrec.o
	$(LD) -o $@ logintest.o $(LDFLAGS) loginrec.o -lopenbsd-compat -lssh $(LIBS)

$(MANPAGES): $(MANPAGES_IN)
	if test "$(MANTYPE)" = "cat"; then \
		manpage=$(srcdir)/`echo $@ | sed 's/\.[1-9]\.out$$/\.0/'`; \
	else \
		manpage=$(srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	fi; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

$(CONFIGFILES): $(CONFIGFILES_IN)
	conffile=`echo $@ | sed 's/.out$$//'`; \
	$(FIXPATHSCMD) $(srcdir)/$${conffile} > $@

# fake rule to stop make trying to compile moduli.o into a binary "moduli.o"
moduli:
	echo

clean:	regressclean
	rm -f *.o *.a $(TARGETS) logintest config.cache config.log
	rm -f *.out core survey
	(cd openbsd-compat && $(MAKE) clean)

distclean:	regressclean
	rm -f *.o *.a $(TARGETS) logintest config.cache config.log
	rm -f *.out core opensshd.init openssh.xml
	rm -f Makefile buildpkg.sh config.h config.status
	rm -f survey.sh openbsd-compat/regress/Makefile *~ 
	rm -rf autom4te.cache
	(cd openbsd-compat && $(MAKE) distclean)
	(cd tests/CA && $(MAKE) distclean)
	if test -d pkg ; then \
		rm -fr pkg ; \
	fi

veryclean: distclean
	rm -f configure config.h.in *.0

cleandir: veryclean

mrproper: veryclean

realclean: veryclean

catman-do:
	@for f in $(MANPAGES_IN) ; do \
		base=`echo $$f | sed 's/\..*$$//'` ; \
		echo "$$f -> $$base.0" ; \
		LANG=C LANGUAGE=C LC_ALL=C \
		$(MANFMT) $$f | cat -v | sed -e 's/.\^H//g' \
			>$$base.0 ; \
	done

distprep:
	$(AUTORECONF)
	-rm -rf autom4te.cache
	@test -n "$(MANFMT)" && echo "run 'make -f Makefile.in catman-do MANFMT=....' with appropriate for you host MANFMT macro"

install: $(CONFIGFILES) $(MANPAGES) $(TARGETS) install-files install-sysconf host-key check-config
install-nokeys: $(CONFIGFILES) $(MANPAGES) $(TARGETS) install-files install-sysconf
install-nosysconf: $(CONFIGFILES) $(MANPAGES) $(TARGETS) install-files

check-config:
	-$(DESTDIR)$(sbindir)/sshd -t -f $(DESTDIR)$(sysconfdir)/sshd_config

install-files:
	$(srcdir)/mkinstalldirs $(DESTDIR)$(bindir)
	$(srcdir)/mkinstalldirs $(DESTDIR)$(sbindir)
	$(srcdir)/mkinstalldirs $(DESTDIR)$(mandir)
	$(srcdir)/mkinstalldirs $(DESTDIR)$(mandir)/$(mansubdir)1
	$(srcdir)/mkinstalldirs $(DESTDIR)$(mandir)/$(mansubdir)5
	$(srcdir)/mkinstalldirs $(DESTDIR)$(mandir)/$(mansubdir)8
	$(srcdir)/mkinstalldirs $(DESTDIR)$(libexecdir)
	$(srcdir)/mkinstalldirs $(DESTDIR)$(sshcadir)
	$(srcdir)/mkinstalldirs $(DESTDIR)$(piddir)
	(umask 022 ; $(srcdir)/mkinstalldirs $(DESTDIR)$(PRIVSEP_PATH))
	$(INSTALL) -m 0755 $(STRIP_OPT) ssh$(EXEEXT) $(DESTDIR)$(bindir)/ssh$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) scp$(EXEEXT) $(DESTDIR)$(bindir)/scp$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) ssh-add$(EXEEXT) $(DESTDIR)$(bindir)/ssh-add$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) ssh-agent$(EXEEXT) $(DESTDIR)$(bindir)/ssh-agent$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) ssh-keygen$(EXEEXT) $(DESTDIR)$(bindir)/ssh-keygen$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) ssh-keyscan$(EXEEXT) $(DESTDIR)$(bindir)/ssh-keyscan$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) sshd$(EXEEXT) $(DESTDIR)$(sbindir)/sshd$(EXEEXT)
	$(INSTALL) -m 4711 $(STRIP_OPT) ssh-keysign$(EXEEXT) $(DESTDIR)$(SSH_KEYSIGN)$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) ssh-pkcs11-helper$(EXEEXT) $(DESTDIR)$(SSH_PKCS11_HELPER)$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) sftp$(EXEEXT) $(DESTDIR)$(bindir)/sftp$(EXEEXT)
	$(INSTALL) -m 0755 $(STRIP_OPT) sftp-server$(EXEEXT) $(DESTDIR)$(SFTP_SERVER)$(EXEEXT)
	$(INSTALL) -m 644 ssh.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/ssh.1
	$(INSTALL) -m 644 scp.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/scp.1
	$(INSTALL) -m 644 ssh-add.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-add.1
	$(INSTALL) -m 644 ssh-agent.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-agent.1
	$(INSTALL) -m 644 ssh-keygen.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-keygen.1
	$(INSTALL) -m 644 ssh-keyscan.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-keyscan.1
	$(INSTALL) -m 644 moduli.5.out $(DESTDIR)$(mandir)/$(mansubdir)5/moduli.5
	$(INSTALL) -m 644 sshd_config.5.out $(DESTDIR)$(mandir)/$(mansubdir)5/sshd_config.5
	$(INSTALL) -m 644 ssh_config.5.out $(DESTDIR)$(mandir)/$(mansubdir)5/ssh_config.5
	$(INSTALL) -m 644 ssh_engine.5.out $(DESTDIR)$(mandir)/$(mansubdir)5/ssh_engine.5
	$(INSTALL) -m 644 sshd.8.out $(DESTDIR)$(mandir)/$(mansubdir)8/sshd.8
	$(INSTALL) -m 644 sftp.1.out $(DESTDIR)$(mandir)/$(mansubdir)1/sftp.1
	$(INSTALL) -m 644 sftp-server.8.out $(DESTDIR)$(mandir)/$(mansubdir)8/sftp-server.8
	$(INSTALL) -m 644 ssh-keysign.8.out $(DESTDIR)$(mandir)/$(mansubdir)8/ssh-keysign.8
	$(INSTALL) -m 644 ssh-pkcs11-helper.8.out $(DESTDIR)$(mandir)/$(mansubdir)8/ssh-pkcs11-helper.8
	-rm -f $(DESTDIR)$(bindir)/slogin
	ln -s ./ssh$(EXEEXT) $(DESTDIR)$(bindir)/slogin
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/slogin.1
	ln -s ./ssh.1 $(DESTDIR)$(mandir)/$(mansubdir)1/slogin.1

install-sysconf:
	if [ ! -d $(DESTDIR)$(sysconfdir) ]; then \
		$(srcdir)/mkinstalldirs $(DESTDIR)$(sysconfdir); \
	fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/ssh_config ]; then \
		$(INSTALL) -m 644 ssh_config.out $(DESTDIR)$(sysconfdir)/ssh_config; \
	else \
		echo "$(DESTDIR)$(sysconfdir)/ssh_config already exists, install will not overwrite"; \
	fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/sshd_config ]; then \
		$(INSTALL) -m 644 sshd_config.out $(DESTDIR)$(sysconfdir)/sshd_config; \
	else \
		echo "$(DESTDIR)$(sysconfdir)/sshd_config already exists, install will not overwrite"; \
	fi
	@if [ ! -f $(DESTDIR)$(sysconfdir)/moduli ]; then \
		if [ -f $(DESTDIR)$(sysconfdir)/primes ]; then \
			echo "moving $(DESTDIR)$(sysconfdir)/primes to $(DESTDIR)$(sysconfdir)/moduli"; \
			mv "$(DESTDIR)$(sysconfdir)/primes" "$(DESTDIR)$(sysconfdir)/moduli"; \
		else \
			$(INSTALL) -m 644 moduli.out $(DESTDIR)$(sysconfdir)/moduli; \
		fi ; \
	else \
		echo "$(DESTDIR)$(sysconfdir)/moduli already exists, install will not overwrite"; \
	fi

host-key: ssh-keygen$(EXEEXT)
	@if [ -z "$(DESTDIR)" ] ; then \
		if [ -f "$(sysconfdir)/ssh_host_key" ] ; then \
			echo "$(sysconfdir)/ssh_host_key already exists, skipping." ; \
		else \
			./ssh-keygen -t rsa1 -f $(sysconfdir)/ssh_host_key -N "" ; \
		fi ; \
		if [ -f $(sysconfdir)/ssh_host_dsa_key ] ; then \
			echo "$(sysconfdir)/ssh_host_dsa_key already exists, skipping." ; \
		else \
			./ssh-keygen -t dsa -f $(sysconfdir)/ssh_host_dsa_key -N "" ; \
		fi ; \
		if [ -f $(sysconfdir)/ssh_host_rsa_key ] ; then \
			echo "$(sysconfdir)/ssh_host_rsa_key already exists, skipping." ; \
		else \
			./ssh-keygen -t rsa -f $(sysconfdir)/ssh_host_rsa_key -N "" ; \
		fi ; \
		if [ -z "" ] ; then \
		    if [ -f $(sysconfdir)/ssh_host_ecdsa_key ] ; then \
			echo "$(sysconfdir)/ssh_host_ecdsa_key already exists, skipping." ; \
		    else \
			./ssh-keygen -t ecdsa -f $(sysconfdir)/ssh_host_ecdsa_key -N "" ; \
		    fi ; \
		fi ; \
	fi ;

host-key-force: ssh-keygen$(EXEEXT)
	./ssh-keygen -t rsa1 -f $(DESTDIR)$(sysconfdir)/ssh_host_key -N ""
	./ssh-keygen -t dsa -f $(DESTDIR)$(sysconfdir)/ssh_host_dsa_key -N ""
	./ssh-keygen -t rsa -f $(DESTDIR)$(sysconfdir)/ssh_host_rsa_key -N ""
	test -z "" && ./ssh-keygen -t ecdsa -f $(DESTDIR)$(sysconfdir)/ssh_host_ecdsa_key -N ""

uninstallall:	uninstall
	-rm -f $(DESTDIR)$(sysconfdir)/ssh_config
	-rm -f $(DESTDIR)$(sysconfdir)/sshd_config
	-rmdir $(DESTDIR)$(sysconfdir)
	-rmdir $(DESTDIR)$(bindir)
	-rmdir $(DESTDIR)$(sbindir)
	-rmdir $(DESTDIR)$(mandir)/$(mansubdir)1
	-rmdir $(DESTDIR)$(mandir)/$(mansubdir)8
	-rmdir $(DESTDIR)$(mandir)
	-rmdir $(DESTDIR)$(libexecdir)

uninstall:
	-rm -f $(DESTDIR)$(bindir)/slogin
	-rm -f $(DESTDIR)$(bindir)/ssh$(EXEEXT)
	-rm -f $(DESTDIR)$(bindir)/scp$(EXEEXT)
	-rm -f $(DESTDIR)$(bindir)/ssh-add$(EXEEXT)
	-rm -f $(DESTDIR)$(bindir)/ssh-agent$(EXEEXT)
	-rm -f $(DESTDIR)$(bindir)/ssh-keygen$(EXEEXT)
	-rm -f $(DESTDIR)$(bindir)/ssh-keyscan$(EXEEXT)
	-rm -f $(DESTDIR)$(bindir)/sftp$(EXEEXT)
	-rm -f $(DESTDIR)$(sbindir)/sshd$(EXEEXT)
	-rm -r $(DESTDIR)$(SFTP_SERVER)$(EXEEXT)
	-rm -f $(DESTDIR)$(SSH_KEYSIGN)$(EXEEXT)
	-rm -f $(DESTDIR)$(SSH_PKCS11_HELPER)$(EXEEXT)
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/ssh.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/scp.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-add.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-agent.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-keygen.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/sftp.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/ssh-keyscan.1
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)8/sshd.8
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)8/sftp-server.8
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)8/ssh-keysign.8
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)8/ssh-pkcs11-helper.8
	-rm -f $(DESTDIR)$(mandir)/$(mansubdir)1/slogin.1


# Target check is more common for the projects using autoXXXX tools
check: tests

tests interop-tests:	$(TARGETS)
	BUILDDIR=`pwd`; \
	[ -d `pwd`/regress ]  ||  mkdir -p `pwd`/regress; \
	[ -f `pwd`/regress/Makefile ]  || \
	    ln -s `cd $(srcdir) && pwd`/regress/Makefile `pwd`/regress/Makefile ; \
	TEST_SHELL="sh"; \
	TEST_SSH_SSH="$${BUILDDIR}/ssh"; \
	TEST_SSH_SSHD="$${BUILDDIR}/sshd"; \
	TEST_SSH_SSHAGENT="$${BUILDDIR}/ssh-agent"; \
	TEST_SSH_SSHADD="$${BUILDDIR}/ssh-add"; \
	TEST_SSH_SSHKEYGEN="$${BUILDDIR}/ssh-keygen"; \
	TEST_SSH_SSHPKCS11HELPER="$${BUILDDIR}/ssh-pkcs11-helper"; \
	TEST_SSH_SSHKEYSCAN="$${BUILDDIR}/ssh-keyscan"; \
	TEST_SSH_SFTP="$${BUILDDIR}/sftp"; \
	TEST_SSH_SFTPSERVER="$${BUILDDIR}/sftp-server"; \
	TEST_SSH_PLINK="plink"; \
	TEST_SSH_PUTTYGEN="puttygen"; \
	TEST_SSH_CONCH="conch"; \
	TEST_SSH_IPV6="yes" ; \
	TEST_SSH_ECC="yes" ; \
	TEST_SSH_SHA256="yes" ; \
	cd $(srcdir)/regress || exit $$?; \
	$(MAKE) \
		.OBJDIR="$${BUILDDIR}/regress" \
		.CURDIR="`pwd`" \
		BUILDDIR="$${BUILDDIR}" \
		OBJ="$${BUILDDIR}/regress/" \
		PATH="$${BUILDDIR}:$${PATH}" \
		TEST_SHELL="$${TEST_SHELL}" \
		TEST_SSH_SSH="$${TEST_SSH_SSH}" \
		TEST_SSH_SSHD="$${TEST_SSH_SSHD}" \
		TEST_SSH_SSHAGENT="$${TEST_SSH_SSHAGENT}" \
		TEST_SSH_SSHADD="$${TEST_SSH_SSHADD}" \
		TEST_SSH_SSHKEYGEN="$${TEST_SSH_SSHKEYGEN}" \
		TEST_SSH_SSHPKCS11HELPER="$${TEST_SSH_SSHPKCS11HELPER}" \
		TEST_SSH_SSHKEYSCAN="$${TEST_SSH_SSHKEYSCAN}" \
		TEST_SSH_SFTP="$${TEST_SSH_SFTP}" \
		TEST_SSH_SFTPSERVER="$${TEST_SSH_SFTPSERVER}" \
		TEST_SSH_PLINK="$${TEST_SSH_PLINK}" \
		TEST_SSH_PUTTYGEN="$${TEST_SSH_PUTTYGEN}" \
		TEST_SSH_CONCH="$${TEST_SSH_CONCH}" \
		TEST_SSH_IPV6="$${TEST_SSH_IPV6}" \
		TEST_SSH_ECC="$${TEST_SSH_ECC}" \
		TEST_SSH_SHA256="$${TEST_SSH_SHA256}" \
		EXEEXT="$(EXEEXT)" \
		$@ && echo all mainstream tests passed
	$(MAKE) check-certs

check-certs: $(TARGETS)
	@BUILDDIR="`pwd`"; \
	( cd "tests/CA" && \
	$(MAKE) \
		TEST_SSH_SSH="$${BUILDDIR}/ssh" \
		TEST_SSH_SSHD="$${BUILDDIR}/sshd" \
		TEST_SSH_SSHAGENT="$${BUILDDIR}/ssh-agent" \
		TEST_SSH_SSHADD="$${BUILDDIR}/ssh-add" \
		TEST_SSH_SSHKEYGEN="$${BUILDDIR}/ssh-keygen" \
		TEST_SSH_SSHKEYSCAN="$${BUILDDIR}/ssh-keyscan" \
		TEST_SSH_SFTP="$${BUILDDIR}/sftp" \
		TEST_SSH_SFTPSERVER="$${BUILDDIR}/sftp-server" \
		$@ )

compat-tests: $(LIBCOMPAT)
	(cd openbsd-compat/regress && $(MAKE))

regressclean:
	if [ -f regress/Makefile ] && [ -r regress/Makefile ]; then \
		(cd regress && $(MAKE) clean) \
	fi
	(cd tests/CA && $(MAKE) clean)

survey: survey.sh ssh
	@$(SHELL) ./survey.sh > survey
	@echo 'The survey results have been placed in the file "survey" in the'
	@echo 'current directory.  Please review the file then send with'
	@echo '"make send-survey".'

send-survey:	survey
	mail portable-survey@mindrot.org <survey

package: $(CONFIGFILES) $(MANPAGES) $(TARGETS)
	if [ "no" = yes ]; then \
		sh buildpkg.sh; \
	fi

# Usefull only if build is in source tree.
# Outside source tree (VPATH build) result is not correct.
depend:
	(cd openbsd-compat && $(MAKE) $@)
	makedepend -- $(CPPFLAGS) $(CFLAGS) -- $(srcdir)/*.c
