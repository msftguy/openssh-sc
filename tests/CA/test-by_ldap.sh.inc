#
# Copyright (c) 2004-2007,2011 Roumen Petrov, Sofia, Bulgaria
# All rights reserved.
#
# Redistribution and use of this script, with or without modification, is
# permitted provided that the following conditions are met:
#
# 1. Redistributions of this script must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
#  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# DESCRIPTION: Test OpenSSH client authentication:
#  - "IdentityFile" contain private key and x509 certificate;
#  - "AuthorizedKeysFile" contain certificate Subject;
#  - authorization against:
#    - LDAP, without CRL file and hash-dir
#


LDAP_SETUP_LOG="${CWD}/ldap_setup.log"
LDAPD_PID="${CWD}/slapd.pid"
LDAPD_ARGS="${CWD}/slapd.args"
LDAPD_CFG="${CWD}/slapd.conf"

if test -z "${LDAP_BINDIR}"; then
  LDAPADD=ldapadd
else
  LDAPADD="${LDAP_BINDIR}/ldapadd"
fi


# ===
#args:
#  $1 - info. message for valid cert.
#  $2 - request valid cert. to fail flag
#  $3 - info. message for revoked cert.
#  $4 - request revoked cert. to fail flag
test_all_keys () {
  for type in ${SSH_SIGN_TYPES}; do
    for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
      identity_file="${SSH_CLIENTKEY}-${type}"
      creX509AuthorizedKeysFile "${identity_file}" &&
      runTest "${identity_file}" \
        "${identity_file}" "$1" "$2" || return $?

      identity_file="${SSH_CLIENTKEY}-${type}-revoked"
      creX509AuthorizedKeysFile "${identity_file}" &&
      runTest "${identity_file}" \
        "${identity_file}" "$3" "$4" || return $?
    done
  done
  return 0
}


# ===
creTestLDAPDcfgFile() {
(
  cat <<EOF
include		$CWD/ldap/slapd.conf.tmpl

# dbms backend settings must be in same file !
# this is required for openldap version 2.3.32(but not for <= 2.3.20,2.2.x,2.1.x)
database	$SSH_LDAP_DB
suffix		"$SSH_LDAP_DC"
rootdn		"cn=Manager,$SSH_LDAP_DC"
rootpw		secret

directory	$CWD/ldap/data
index	objectClass	eq

pidfile		$LDAPD_PID
argsfile	$LDAPD_ARGS
EOF
) > ${LDAPD_CFG}
}


# ===
creTestLDAPDCAldifFile() {
(

  for level in 0; do
    N="$CAKEY_PREFIX"-root${level}.crt
    if test ! -f "ldap/$N.der"; then
      $OPENSSL x509 \
        -in "$SSH_CACERTDIR/$N".pem \
        -out ldap/"$N".der -outform DER \
        || exit $?
    fi
  done

  for type in ${SSH_SIGN_TYPES}; do
    N="${CAKEY_PREFIX}-${type}.crt"
    if test ! -f "ldap/${N}.der"; then
      ${OPENSSL} x509 \
        -in "${SSH_CACERTDIR}/${N}".pem \
        -out "ldap/${N}.der" -outform DER \
        || exit $?
    fi

    N="${CAKEY_PREFIX}-${type}.crl"
    if test ! -f "ldap/${N}.der"; then
      ${OPENSSL} crl \
        -in "${SSH_CACRLDIR}/${N}".pem \
        -out "ldap/${N}.der" -outform DER \
        || exit $?
    fi
  done
) || return $?

(
  for level in 0; do
    cat <<EOF
# "CN=OpenSSH TestCA level 0,OU=${SSH_DN_OU} $type keys,OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"
dn:`utf8base64 "CN=OpenSSH TestCA level $level,OU=${SSH_DN_OU} level $level,OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"`
objectClass: inetOrgPerson
objectClass: pkiCA
cACertificate;binary:< file://${CWD}/ldap/catest-root${level}.crt.der
cn: OpenSSH TestCA level 0
sn: OpenSSH TestCA level 0
ou:`utf8base64 "${SSH_DN_OU} level $level"`
ou:`utf8base64 "${SSH_DN_OU}"`
o:`utf8base64 "${SSH_DN_O}"`
l:`utf8base64 "${SSH_DN_L}"`
st: ${SSH_DN_ST}

EOF
  done

  for type in ${SSH_SIGN_TYPES}; do
    cat <<EOF
# "CN=OpenSSH ${type} TestCA key,OU=${SSH_DN_OU} $type keys,OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"
dn:`utf8base64 "CN=OpenSSH ${type} TestCA key,OU=${SSH_DN_OU} $type keys,OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"`
objectClass: inetOrgPerson
objectClass: pkiCA
cACertificate;binary:< file://${CWD}/ldap/catest-${type}.crt.der
certificateRevocationList;binary:< file://${CWD}/ldap/catest-${type}.crl.der
cn: OpenSSH ${type} TestCA key
sn: OpenSSH ${type} TestCA key
ou:`utf8base64 "${SSH_DN_OU} ${type} keys"`
ou:`utf8base64 "${SSH_DN_OU}"`
o:`utf8base64 "${SSH_DN_O}"`
l:`utf8base64 "${SSH_DN_L}"`
st: ${SSH_DN_ST}

EOF
  done
) > ldap/ca.ldif
}


# ===
runLDAPdaemon() {
  if test -f "${LDAPD_PID}"; then
    echo "${warn}slapd pid file exist!${norm}" >&2
  fi

  printf '  %s' "starting ${extd}LDAP${norm} server on ${attn}${LDAPD_URL}${norm}"
  #for errors check syslog files(LOCAL4 facility)
  $SUDO "${LDAP_LIBEXECDIR}/slapd" \
    -f "${LDAPD_CFG}" \
    -h "${LDAPD_URL}" \
  > /dev/null 2>&1

  sleep 2
  K=0
  while test $K -le 5; do
    if test -f "${LDAPD_PID}"; then
      break
    fi
    sleep 1
    K=`expr $K + 1`
  done

  test -r "${LDAPD_PID}"; show_status $?
  if test ! -r "${LDAPD_PID}"; then
    printf "${warn}cannot start slapd:${norm} " >&2
    error_file_not_readable "${LDAPD_PID}"
    return 33
  fi
  return 0
}


killLDAPdaemon() {
(
  $SUDO kill `cat "${LDAPD_PID}" 2>/dev/null` > /dev/null 2>&1
  K=0
  while test $K -le 9; do
    if test ! -f "${LDAPD_PID}"; then
      break
    fi
    sleep 1
    K=`expr $K + 1`
  done
  if test -f "${LDAPD_PID}"; then
    $SUDO kill -9 `cat "${LDAPD_PID}" 2>/dev/null` > /dev/null 2>&1
    sleep 1
    $SUDO rm -f "${LDAPD_PID}" > /dev/null 2>&1
    $SUDO rm -f "${LDAPD_ARGS}" > /dev/null 2>&1
  fi
  rm -f "${LDAPD_CFG}"
  exit 0
)
}


initLDAPdb() {
  create_empty_file "${LDAP_SETUP_LOG}" || return $?

  "${LDAPADD}" \
    -x -w secret -D "cn=Manager,${SSH_LDAP_DC}" \
    -H "${LDAPD_URL}" \
    -f "${CWD}/ldap/base.ldif" \
  >> "${LDAP_SETUP_LOG}" 2>&1 || return $?

  "${LDAPADD}" \
    -x -w secret -D "cn=Manager,${SSH_LDAP_DC}" \
    -H "${LDAPD_URL}" \
    -f "${CWD}/ldap/ca.ldif" \
  >> "${LDAP_SETUP_LOG}" 2>&1 || return $?

  return 0
}


# ===
# $1 - LDAP version
testLDAP() {
  printSeparator
  echo "Begin test with LDAP ${extd}version${norm} ${attn}$1${norm}"

  creTestLDAPDcfgFile
  creTestLDAPDCAldifFile
  creTestSSHDcfgFile

#openssh config parser limitation
SSH_CONF_LDAP_DC=`echo ${SSH_LDAP_DC} | sed -e 's|=|%3D|g' -e 's|,|%2C|'`
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
CAldapVersion $1
CAldapURL ${LDAPD_URL}/${SSH_CONF_LDAP_DC}
#TODO:MandatoryCRL yes
EOF

  runSSHdaemon || return $?
  (
    rm -f "${CWD}/ldap/data"/*
    runLDAPdaemon
    (
      initLDAPdb || exit $?

      test_all_keys "" "" "${warn}!${norm}" "Yes"
    ); retval=$?
    killLDAPdaemon
    exit ${retval}
  ); retval=$?
  killSSHdaemon

  return ${retval}
}


# ===
LDAPtestBREAK() {
  echo
  killLDAPdaemon
  testBREAK
}

trap LDAPtestBREAK INT QUIT ABRT KILL TERM || exit 1


# ===

do_test () {
  if test "x${SSH_LDAP_ENABLED}" = "xno"; then
    echo "* ${extd}LDAP${norm} is ${attn}disabled${norm}"
    return 1
  fi
  echo "* ${extd}against ${attn}CALdapUrl${norm}:"

  testLDAP 2 &&
  testLDAP 3
}
