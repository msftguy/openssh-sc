#
# Copyright (c) 2004,2011 Roumen Petrov, Sofia, Bulgaria
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
#  - validation against:
#    - OCSP provider from certificate
#    - specified in configuration OCSP provider
#    - TODO:specified OCSP provider with revoked provider certificate
#  Note:
#  Due OpenSSL limitation no one of tests start OCSP provider with dsa key.
#


# ===
openssl_ocsp_tmout() {
(
  if test -z "$SSH_OPENSSL_OCSP_TMOUT"; then
    sleep 1
    exit 0
  fi

  count=$SSH_OPENSSL_OCSP_TMOUT
  echo "OpenSSL OCSP responder socket timeout ${count}[sec.]" >&2
  while test ${count} -gt 0; do
    printf 'O'
    sleep 1
    count=`expr ${count} - 1`
  done
  printf 'X\n'
  sleep 1
)
}


# ===
killResponders() {
(
  if test -z "$SSH_OPENSSL_OCSP_TMOUT"; then
  (
    has=""
    for pidfile in va-*.pid; do
      if test -r "${pidfile}"; then
        kill `cat "${pidfile}"` > /dev/null 2>&1
        has="yes"
      fi
    done
    if test -n "${has}"; then
      openssl_ocsp_tmout
    fi
  )
  fi
  (
    has=""
    for pidfile in va-*.pid; do
      if test -r "${pidfile}"; then
        kill -9 `cat "${pidfile}"` > /dev/null 2>&1
        rm -f "${pidfile}"
        has="yes"
      fi
    done
    if test -n "${has}"; then
      openssl_ocsp_tmout
    fi
  )
  :
)
}


# ===
OCSPtestBREAK() {
  echo
  killResponders
  testBREAK
}

trap OCSPtestBREAK INT QUIT ABRT KILL TERM || exit 1


# ===
#args:
#  $1 - port
#env. vars:
#  OCSP_RESPKEY
#  type
runResponder() {
(
  port=$1

  pidfile="va-${port}.pid"
  test -r "${pidfile}" && exit 1

  printf '  %s' "starting OCSP ${extd}responder${norm}(${attn}${type}${norm}) on ${attn}${SSHD_LISTENADDRESS}:${port}${norm}"
  (
  ${OPENSSL} ocsp \
    -CA      "${SSH_CACERTDIR}/${CAKEY_PREFIX}-${type}.crt.pem" \
    -rsigner "${OCSP_RESPKEY}-${type}.crt" \
    -rkey    "${OCSP_RESPKEY}" \
    -index   "${SSH_CAROOT}/index-${type}.txt" \
    -host ${SSHD_LISTENADDRESS} \
    -port ${port} 2> va-${type}.log &
  pid=$!
  echo ${pid} > "${pidfile}"
  wait ${pid}
  rm -f "${pidfile}"
  ) 2> /dev/null &

  sleep 1
  test -r "${pidfile}"; show_status $?
)
}


# ===
test_ocsp_cert () {
(
  printSeparator
  echo "Begin test ${extd}against${norm} OCSP provider from ${attn}certificate${norm} ..."

  retval=1
  for OCSP_RESPKEY in ${TEST_OCSP_RESPKEYS}; do
    printSeparator
    echo "  respoder key base ${attn}${OCSP_RESPKEY}${norm} ..."

    creTestSSHDcfgFile
    cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
VAType ocspcert
EOF

    port=${SSH_VA_BASEPORT}
    for type in ${SSH_SIGN_TYPES}; do
      runResponder ${port}; retval=$?
      if test ${retval} -ne 0; then
        break
      fi
      port=`expr ${port} + 1`
    done
    if test ${retval} -eq 0; then
      runSSHdaemon &&
      (
        for type in ${SSH_SIGN_TYPES}; do
          test_by_keytype || exit $?
        done
      ); retval=$?
      killSSHdaemon
    fi
    killResponders
    if test ${retval} -ne 0; then
      exit ${retval}
    fi
  done

  exit ${retval}
)
}


# ===
#env. vars:
#  type
test_by_keytype() {
(
  for SSH_CLIENTKEY in ${TEST_SSH_CLIENTKEYS}; do
    identity_file="${SSH_CLIENTKEY}-${type}"
    creX509AuthorizedKeysFile "${identity_file}" &&
    runTest "${identity_file}" \
      "${identity_file}" "" "" || exit $?

    identity_file="${SSH_CLIENTKEY}-${type}-revoked"
    creX509AuthorizedKeysFile "${identity_file}" &&
    runTest "${SSH_CLIENTKEY}-${type}${warn}-revoked${norm}" \
      "${identity_file}" "" "Yes" || exit $?
  done
)
}


# ===
test_ocsp_spec () {
(
  printSeparator
  echo "Begin test ${extd}against${norm} ${attn}specified${norm} OCSP provider ..."

  #OpenSSL OCSP responder support only one CA!
  #For each signature type we have different CA, i.e. we must start
  #corresponding OCSP responder.
  #Note: OpenSSL OCSP responder doesn't support dsa keys!!!
  retval=1
  for OCSP_RESPKEY in ${TEST_OCSP_RESPKEYS}; do
    printSeparator
    echo "  respoder key base ${attn}${OCSP_RESPKEY}${norm} ..."

    for type in ${SSH_SIGN_TYPES}; do
      creTestSSHDcfgFile
      cat >> "$SSHD_CFG" <<EOF
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
VAType ocspspec
VAOCSPResponderURL http://${SSHD_LISTENADDRESS}:${SSH_VA_BASEPORT}
#VACertificateFile `pwd`/${OCSP_RESPKEY}-${type}.crt
EOF

      runResponder ${SSH_VA_BASEPORT} &&
      runSSHdaemon &&
      test_by_keytype; retval=$?
      killSSHdaemon
      killResponders
      if test ${retval} -ne 0; then
        exit ${retval}
      fi
    done
  done

  exit ${retval}
)
}


# ===

do_test () {
  if test "x${SSH_OCSP_ENABLED}" = "xno"; then
    echo "* ${extd}OCSP${norm} is ${attn}disabled${norm}"
    return 1
  fi
  echo "* ${extd}against ${attn}CACertificateFile${norm} and ${attn}OCSP provider${norm}:"

  test_ocsp_cert &&
  test_ocsp_spec
}
