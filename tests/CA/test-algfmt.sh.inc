#
# Copyright (c) 2011 Roumen Petrov, Sofia, Bulgaria
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
#  - server accept different publickey algorithms based on certificates.
#  - client use different digest algorithms.
# Note that "Host-Based Authentication" we cannot test without to install.
#


# ===
#env. vars:
#  alg
testAlgFmt () {
  printSeparator

# NOTE:
# The default for certificates with RSA key is:
#   X509KeyAlgorithm x509v3-sign-rsa,rsa-md5
#   X509KeyAlgorithm x509v3-sign-rsa,rsa-sha1
# The default for certificates with DSA key is:
#  X509KeyAlgorithm x509v3-sign-dss,dss-asn1
#  X509KeyAlgorithm x509v3-sign-dss,dss-raw

  case $alg in
    x509v3-sign-rsa*) fmt_list="rsa-sha1 rsa-md5";;
    x509v3-sign-dss*) fmt_list="dss-raw dss-asn1";;
  esac

  for fmt_srv in $fmt_list; do
    echo "  - server: only ${attn}${alg}${norm} algorithm with ${attn}${fmt_srv}${norm} digest"

    creTestSSHDcfgFile
    if test "x$SSH_X509STORE_DISABLED" != "xyes"; then
      cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF
    fi
    cat >> "$SSHD_CFG" <<EOF
PubkeyAlgorithms $alg
X509KeyAlgorithm $alg,$fmt_srv
EOF
    case $fmt_srv in
      *md5)
        if test -n "$OPENSSL_FIPS"; then
          if "$TEST_SSH_SSHD" -f "$SSHD_CFG" -t >> "$SSHD_LOG" 2>&1; then
            echo "    server in ${attn}FIPS${norm} mode - accept ${attn}$fmt_srv${norm} digest!"
            return 99
          else
            echo "    server in ${attn}FIPS${norm} mode - skipping ..."
            continue
          fi
        fi
        ;;
    esac


    runSSHdaemon || return $?
    (
      for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
        case $SSH_CLIENTKEY in
          *rsa) keytype="rsa";;
          *dsa) keytype="dsa";;
          *)    echo "${warn}unknown client key type${norm}"
                exit 1;;
        esac
        case $alg in
          x509v3-sign-rsa*) test "$keytype" = "rsa" || continue;;
          x509v3-sign-dss*) test "$keytype" = "dsa" || continue;;
          *)                echo "${warn}unknown X.509 alg${norm}"
                            exit 1;;
        esac

        for type in $SSH_SIGN_TYPES; do
          identity_file="$SSH_CLIENTKEY-$type"
          "$TEST_SSH_SSHKEYGEN" -f "$identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || exit $?

          for fmt_cln in $fmt_list; do
            TEST_CLIENT_CFG="\
X509KeyAlgorithm $alg,$fmt_cln
"
            if test $fmt_srv = $fmt_cln; then
              must_fail=no
              typemsg="$identity_file $fmt_cln"
            else
              must_fail=yes
              typemsg="$identity_file $fmt_cln ${warn}!${norm}"
            fi
            must_fail_err_txt=

            if test -n "$OPENSSL_FIPS"; then
              case $fmt_cln in
                *md5)
                  typemsg="$identity_file $fmt_cln ${warn}FIPS mode!${norm}"
                  must_fail_err_txt='rsa-md5 in not enabled in FIPS mode'
                  ;;
              esac
            fi

            runTest "$typemsg" \
              "$identity_file" "" $must_fail $must_fail_err_txt || exit $?
          done
        done
      done
    ); retval=$?
    killSSHdaemon

    test $retval -ne 0 && break
  done

  return $retval
}


# ===

do_test () {
  retval=0
  if test "x$SSH_X509STORE_DISABLED" = "xyes"; then
    echo "* ${extd}with different digest ${attn}algorithms${norm}:"
  else
    echo "* ${extd}against ${attn}CACertificateFile${norm} and different digest ${attn}algorithms${norm}:"
  fi

  for alg in \
    "x509v3-sign-rsa" \
    "x509v3-sign-dss" \
  ; do
    testAlgFmt; retval=$?
    test $retval -ne 0 && break
  done
  return $retval
}
