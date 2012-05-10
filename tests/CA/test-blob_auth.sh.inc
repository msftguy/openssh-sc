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
#  - "AuthorizedKeysFile" contain certificate BLOB.
#


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testBLOBautorization () {
  identity_file="${SSH_CLIENTKEY}-${type}"
  if test ! -r "${identity_file}"; then
    error_file_not_readable "${identity_file}"; return $?
  fi

  echo "  using identity file ${identity_file}"
  echo "  creating AuthorizedKeysFile"
  "$TEST_SSH_SSHKEYGEN" -f "${identity_file}" -y 2>/dev/null > "${AUTHORIZEDKEYSFILE}" || return $?
  runTest "${type}" "${identity_file}"\
    "${extd}valid${norm} blob" || return $?

  blob=`cat "${AUTHORIZEDKEYSFILE}"`
  echo $blob | cut -c 1-50 > "${AUTHORIZEDKEYSFILE}"
  runTest "${type}" "${identity_file}"\
    "${warn}invalid${norm} blob" "Yes" || return $?
}


# ===

do_test () {
  retval=0
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}with autorization by x509 ${attn}blob${norm}:"
  else
    echo "* ${extd}against ${attn}CACertificateFile${norm} and autorization by x509 ${attn}blob${norm}:"
  fi

  creTestSSHDcfgFile
  if test "x${SSH_X509STORE_DISABLED}" != "xyes"; then
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF
  fi

  runSSHdaemon || return $?
  (
    for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
      printSeparator
      echo "Begin test with base key_file ${attn}${SSH_CLIENTKEY}${norm} ..."

      for type in ${SSH_SIGN_TYPES}; do
        testBLOBautorization || exit $?
      done
    done
  ); retval=$?
  killSSHdaemon
  return $retval
}
