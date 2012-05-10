#
# Copyright (c) 2006,2011 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" contain private key and self-signed x509 certificate;
#  - "AuthorizedKeysFile" contain certificate BLOB or DN.
#


# ===
#args:
#  $1 - request to fail flag for blob
#  $2 - request to fail flag for DN
test_self() {

  case $1 in
    Y|y|Yes|yes|YES|1)
      blob_msg="${warn}blob${norm}";;
    *)
      blob_msg="${extd}blob${norm}";;
  esac
  case $2 in
    Y|y|Yes|yes|YES|1)
      dn_msg="${warn}DN${norm}";;
    *)
      dn_msg="${extd}DN${norm}";;
  esac

  for keytype in rsa dsa; do
    SSH_CLIENTKEY="selfid_${keytype}"

    for type in ${SSH_SIGN_TYPES}; do
      case $keytype in
        rsa)
          case $type in
            *dsa*) continue;;
          esac
          ;;
        dsa)
          case $type in
            *rsa*) continue;;
          esac
          ;;
      esac

      identity_file="${SSH_CLIENTKEY}-${type}"

      cat "${SSH_CLIENTKEY}.pub" > "${AUTHORIZEDKEYSFILE}" &&
      runTest "" "${identity_file}" \
        "${type} ${blob_msg}" "$1" \
      || return $?

      sshkeytype=`getSSHkeyType "${identity_file}"` || return $?
      subject=`getSubject "${identity_file}"` || return $?

      echo "${sshkeytype} Subject: ${subject}" > "${AUTHORIZEDKEYSFILE}" &&
      runTest "" "${identity_file}" \
        "${type} ${dn_msg}" "$2" \
      || return $?
    done
  done
}

# ===

test_store () {
  retval=0
  echo "  - ${attn}with${norm} self-signed trusted by ${extd}x509store${norm}:"
  printSeparator

  cat selfid_*.crt > $CWD/selfid-bundle

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued no
CACertificateFile $CWD/selfid-bundle
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "no"
  ); retval=$?
  killSSHdaemon
  rm -f $CWD/selfid-bundle
  return $retval
}

# ===

test_pkey_no () {
  retval=0
  echo "  - ${attn}without${norm} self-signed allowed by ${extd}pubkey${norm}:"
  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued no
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "yes" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===

test_pkey_yes () {
  retval=0
  echo "  - ${attn}with${norm} self-signed allowed by ${extd}pubkey${norm}:"
  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued yes
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===
SELFtestBREAK() {
  echo
  rm -f $CWD/selfid-bundle
  testBREAK
}

trap SELFtestBREAK INT QUIT ABRT KILL TERM || exit 1


# ===

do_test () {
  echo "* ${extd}self-signed${norm}:"
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "  ${extd}X.509 store${norm} is ${attn}disabled${norm}"
    echo "  the test is not suitable in this context"
    return 0
  fi

  test_store &&
  test_pkey_no &&
  test_pkey_yes
}
