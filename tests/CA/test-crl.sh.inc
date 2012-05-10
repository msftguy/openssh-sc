#
# Copyright (c) 2002-2004 Roumen Petrov, Sofia, Bulgaria
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
#    - without CRL file and hash-dir
#    - only with CRL file(CARevocationFile)
#    - only with CRL hash-dir(CARevocationPath)
#    - only one CRL file in a hash-dir
#


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
test_nocrl () {
  printSeparator
  echo "Begin test ${extd}without${norm} CRL ${attn}file${norm} and ${attn}hash-dir${norm} ..."

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
    test_all_keys "" "" "" ""; retval=$?
  killSSHdaemon

  return ${retval}
}


# ===
test_crlfile () {
  printSeparator
  echo "Begin test with CRL ${extd}file(${attn}CARevocationFile${norm}) ..."

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  ${SSH_CAROOT}/${CACRLFILE}
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
    test_all_keys "" "" "${warn}!${norm}" "Yes"; retval=$?
  killSSHdaemon

  return ${retval}
}


# ===
test_crldir () {
  printSeparator
  echo "Begin test with CRL ${extd}hash-dir(${attn}CARevocationPath${norm}) ..."

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  ${SSH_CACRLDIR}
EOF

  runSSHdaemon || return $?
    test_all_keys "" "" "${warn}!${norm}" "Yes"; retval=$?
  killSSHdaemon

  return ${retval}
}


# ===
#env. vars:
#  crltype - crl for signature type
test_crlbytype () {
  retval=0

  echo "  - ${extd}with ${attn}${crltype}${norm} only in ${attn}CARevocationPath${norm} ..."

  printf "  creating ${attn}${crltype}${norm} crlfile in hash dir"
  #printf "${warn}"
    rm -f "${CRL_TEST_DIR}"/* 2> /dev/null
    FILE="${SSH_CACRLDIR}/${CAKEY_PREFIX}-${crltype}.crl.pem"
    HASH=`${OPENSSL} crl -out /dev/null -in "${FILE}" -hash`; retval=$?
    if test ${retval} -eq 0; then
      hashfile="${CRL_TEST_DIR}/${HASH}.r0"
      ln -s "${FILE}" "${hashfile}"
      #link might never fail :-(
      test -h "${hashfile}"; retval=$?
    fi
  #printf "${norm}"
  show_status ${retval} || return $?

  (
    for type in ${SSH_SIGN_TYPES}; do
      for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
        identity_file="${SSH_CLIENTKEY}-${type}-revoked"

        creX509AuthorizedKeysFile "${identity_file}" || exit $?

        if test "${type}" = "${crltype}"; then
          runTest "${SSH_CLIENTKEY}-${warn}${type}-revoked${norm}" \
            "${identity_file}" "" "Yes"
        else
          runTest "${identity_file}" \
            "${identity_file}" "" ""
        fi || exit $?
      done
    done
    exit 0
  ); retval=$?

  if test ${retval} -eq 0; then
    rm -f "${hashfile}"; retval=$?
  else
    rm -f "${hashfile}"
  fi
  return ${retval}
}


# ===
test_onlyonecrl () {
  retval=0
  CRL_TEST_DIR="${SSH_CAROOT}/crl-test"

  printSeparator
  echo "Check ${extd}revoked${norm} with only ${attn}one CRL${norm} in ${attn}CARevocationPath${norm} ..."

  mkdir -p "${CRL_TEST_DIR}" || return $?

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  ${CRL_TEST_DIR}
EOF


  runSSHdaemon &&
  (
    for crltype in ${SSH_SIGN_TYPES}; do
      test_crlbytype || exit $?
    done
  ); retval=$?
  killSSHdaemon

  rm -f "${CRL_TEST_DIR}"/* 2> /dev/null
  if test ${retval} -eq 0; then
    rmdir "${CRL_TEST_DIR}"; retval=$?
  else
    rmdir "${CRL_TEST_DIR}"
  fi
  return ${retval}
}


# ===
test_crlpresence_yes () {
  printSeparator
  echo "Begin test with mandatory ${extd}CRL presence ${attn}with${norm} CRL ..."

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  ${SSH_CAROOT}/${CACRLFILE}
CARevocationPath  /crlpath/not/found
MandatoryCRL yes
EOF

  runSSHdaemon || return $?
    test_all_keys "" "" "${warn}!${norm}" "Yes"; retval=$?
  killSSHdaemon

  return ${retval}
}


# ===
test_crlpresence_no () {
  printSeparator
  echo "Begin test with mandatory ${extd}CRL presence ${attn}without${norm} CRL ..."

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
MandatoryCRL yes
EOF

  runSSHdaemon || return $?
    test_all_keys "${warn}!${norm}" "Yes" "${warn}!${norm}" "Yes"; retval=$?
  killSSHdaemon

  return ${retval}
}


# ===

do_test () {
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}X.509 store${norm} is ${attn}disabled${norm}"
    return 1
  fi
  echo "* ${extd}against ${attn}CA CRL${norm} file and/or hash-dir:"

  test_nocrl &&
  test_crlfile &&
  test_crldir &&
  test_onlyonecrl &&
  test_crlpresence_yes &&
  test_crlpresence_no
}
