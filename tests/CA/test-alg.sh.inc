#
# Copyright (c) 2004-2005 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" contain private key and optional x509 certificate;
#  - "AuthorizedKeysFile" contain certificate BLOB.
#  - server accept different publickey algorithms.
# Note that "Host-Based Authentication" we cannot test without to install.
#


# ===
#env. vars:
#  alg
testAlg () {
  printSeparator
  echo "  - only ${attn}${alg}${norm} algorithm"

  creTestSSHDcfgFile
  if test "x${SSH_X509STORE_DISABLED}" != "xyes"; then
    cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF
    fi
  cat >> "$SSHD_CFG" <<EOF
PubkeyAlgorithms $alg
EOF

  runSSHdaemon || return $?
  (
    for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
      case $SSH_CLIENTKEY in
        *rsa) keytype="rsa";;
        *dsa) keytype="dsa";;
        *)    echo "${warn}unknown client key type${norm}"
              exit 1;;
      esac
      case $alg in
        x509v3-sign-*) withcert="yes";;
        *)             withcert="";;
      esac

      if test -z "$withcert"; then
        must_fail=""
        if test "X$alg" = "Xssh-rsa"; then
          test "$keytype" = "rsa" || must_fail="yes"
        else
          test "$keytype" = "dsa" || must_fail="yes"
        fi
      else
        must_fail="yes"
      fi

      identity_file="${SSH_CLIENTKEY}"
      "$TEST_SSH_SSHKEYGEN" -f "${identity_file}" -y 2>/dev/null > "${AUTHORIZEDKEYSFILE}" || exit $?

      if test -n "$must_fail"; then
        typemsg="${identity_file} ${warn}!${norm}"
      else
        typemsg="${identity_file}"
      fi
      runTest "${typemsg}" \
        "${identity_file}" "" "$must_fail" || exit $?

      for type in ${SSH_SIGN_TYPES}; do
        if test -n "$withcert"; then
          must_fail=""
          case $alg in
            x509v3-sign-rsa*) test "$keytype" = "rsa" || must_fail="yes";;
            x509v3-sign-dss*) test "$keytype" = "dsa" || must_fail="yes";;
            *)                echo "${warn}unknown X.509 alg${norm}"
                              exit 1;;
          esac
        else
          must_fail="yes"
        fi

        identity_file="${SSH_CLIENTKEY}-${type}"
        "$TEST_SSH_SSHKEYGEN" -f "${identity_file}" -y 2>/dev/null > "${AUTHORIZEDKEYSFILE}" || exit $?

        if test -n "$must_fail"; then
          typemsg="${identity_file} ${warn}!${norm}"
        else
          typemsg="${identity_file}"
        fi
        runTest "${typemsg}" \
          "${identity_file}" "" "$must_fail" || exit $?
      done
    done
  ); retval=$?
  killSSHdaemon

  return $retval
}


# ===

do_test () {
  retval=0
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}with different publickey ${attn}algorithms${norm}:"
  else
    echo "* ${extd}against ${attn}CACertificateFile${norm} and different publickey ${attn}algorithms${norm}:"
  fi

  for alg in \
    "ssh-rsa" \
    "ssh-dss" \
    "x509v3-sign-rsa" \
    "x509v3-sign-dss" \
  ; do
    testAlg; retval=$?
    if test $retval -ne 0; then
      break
    fi
  done
  return $retval
}
