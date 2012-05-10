#
# Copyright (c) 2002-2004,2011 Roumen Petrov, Sofia, Bulgaria
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
#  - authorization against only one CA certificate in server x509 store.
#


# ===
cre_hash_link () {
  HASH=`$OPENSSL x509 -in "$1" -noout -hash` || return $?

  rm -f "$HASH.0" &&
  ln -s "$1" "$HASH.0" &&
  #link might never fail ;-(
  test -h "$HASH.0"
}


# ===
#env. vars:
#  SSH_CLIENTKEY
#  catype
#  type
testDNautorizations2 () {
  identity_file="${SSH_CLIENTKEY}-${type}"

  creX509AuthorizedKeysFile "${identity_file}" || return $?

  if test "${catype}" = "${type}"; then
    runTest "${extd}${type}${norm}" \
      "${identity_file}"\
      "" ""
  else
    runTest "${type}" \
      "${identity_file}" \
      "${warn}!${norm}" "Yes"
  fi
}


# ===
#env. vars:
#  catype
do_test_catype () {
  echo "  - autorization by x509 ${attn}Subject${norm} against CA key ${attn}${catype}${norm}"

  for type in ${SSH_SIGN_TYPES}; do
    testDNautorizations2 "${catype}" "${type}" || return $?
  done
}


# ===

do_test () {
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}X.509 store${norm} is ${attn}disabled${norm}"
    return 1
  fi
  echo "* ${extd}against ${attn}CACertificatePath${norm}:"

  CRT_TEST_DIR="${SSH_CAROOT}/crt-test"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile /file/not/found
CACertificatePath ${CRT_TEST_DIR}
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF


  runSSHdaemon || return $?
  (
    for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
      printSeparator
      echo "Begin test with base key_file ${attn}${SSH_CLIENTKEY}${norm} ..."

      if test ! -d "${CRT_TEST_DIR}"; then
        mkdir "$CRT_TEST_DIR" || exit $?
      fi
      rm -rf "${CRT_TEST_DIR}/"* 2>/dev/null

      for catype in ${SSH_SIGN_TYPES}; do
        ( cd "$CRT_TEST_DIR" &&
          rm -f "$CRT_TEST_DIR"/* &&
          for level in 0; do
            cre_hash_link "$SSH_CACERTDIR/$CAKEY_PREFIX"-root${level}.crt.pem || exit $?
          done
          cre_hash_link "$SSH_CACERTDIR/${CAKEY_PREFIX}-${catype}.crt.pem"
        ) &&
        do_test_catype; retval=$?
        rm -f "$CRT_TEST_DIR"/*
        if test $retval -ne 0; then
          break
        fi
      done

      rmdir "${CRT_TEST_DIR}"
      if test $retval -ne 0; then
        exit $retval
      fi
    done

    exit 0
  ); retval=$?
  killSSHdaemon
  return $retval
}
