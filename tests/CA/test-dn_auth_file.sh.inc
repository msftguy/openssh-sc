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
#  - "AuthorizedKeysFile" contain certificate "Distinguished Name"/
#    "Subject" in varios formats.
#


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testDNautorizations1 () {
  identity_file="${SSH_CLIENTKEY}-${type}"
  if test ! -r "$identity_file"; then
    error_file_not_readable "${identity_file}"; return $?
  fi

  sshkeytype=`getSSHkeyType "${identity_file}"` || return $?
  subject=`getSubject "${identity_file}"` || return $?

  for subtype in \
    "Subject:" \
    "SuBjecT=" \
    "sUbjecT" \
    "diStinguished name:" \
    "distiNguished-nAme:" \
    "distinguiShed_naMe:" \
    "disTinguishednamE:" \
    "dN:" \
  ; do
    echo "${sshkeytype} ${subtype} ${subject}" > "${AUTHORIZEDKEYSFILE}"
    runTest "${type} ${subtype}" "${identity_file}" "" || return $?
  done

  subtype="subject"
  subject=`getSubject "${identity_file}" -nameopt RFC2253 -nameopt -esc_msb` || return $?
  echo "${sshkeytype} ${subtype} ${subject}" > "${AUTHORIZEDKEYSFILE}"
  runTest "${type} ${subtype} in ${attn}RFC2253${norm} format" "${identity_file}" "" || return $?

  echo "${sshkeytype} ${subtype} ${subject}" | sed -e 's/,/\//'> "${AUTHORIZEDKEYSFILE}"
  runTest "${type} ${subtype} and mixed item-separator symbol" "${identity_file}" "" || return $?

  for subtype in \
    "Invalid" \
    "Subject-" \
  ; do
    echo "${sshkeytype} ${subtype} ${subject}" > "${AUTHORIZEDKEYSFILE}"
    runTest "${type} ${warn}${subtype}${norm}" "${identity_file}" \
      "autorization type" "Yes" || return $?
  done

  subtype="Subject"
  printf "${sshkeytype} ${subtype}," > "${AUTHORIZEDKEYSFILE}"
  runTest "${type} ${warn}empty${norm} ${subtype}" "${identity_file}" \
    "" "Yes" || return $?

  subtype="Subject"
  ( printf "${sshkeytype} ${subtype}"
    echo "${subject}" | cut -c -40
  ) > "${AUTHORIZEDKEYSFILE}"
  runTest "${type} ${warn}invalid${norm} ${subtype}" "${identity_file}" \
    "" "Yes" || return $?

  return 0
}


# ===

do_test () {
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}X.509 store${norm} is ${attn}disabled${norm}"
    return 1
  fi
  echo "* ${extd}against ${attn}CACertificateFile${norm} and autorization by x509 ${attn}'Distinguished Name'${norm}:"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
      printSeparator
      echo "Begin test with base key_file ${attn}${SSH_CLIENTKEY}${norm} ..."

      for type in ${SSH_SIGN_TYPES}; do
        testDNautorizations1 || exit $?
      done
    done
  ); retval=$?
  killSSHdaemon
  return $retval
}
