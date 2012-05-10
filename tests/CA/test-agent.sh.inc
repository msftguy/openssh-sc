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
#  - add a key to agent;
#  - list agent keys;
#  - try to connect with key from agent;
#  - remove the key from agent.
#


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testAgent () {
  identity_file="${SSH_CLIENTKEY}-${type}"
  if test ! -r "${identity_file}"; then
    error_file_not_readable "${identity_file}"; return $?
  fi

  (
    if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
      cat "${identity_file}.pub"
    else
      sshkeytype=`getSSHkeyType "${identity_file}"` || exit $?
      subject=`getSubject "${identity_file}"` || exit $?

      echo "${sshkeytype} Subject: ${subject}"
    fi
  ) > "${AUTHORIZEDKEYSFILE}" || return $?

(
killAgent () {
  "${TEST_SSH_SSHAGENT}" -k > /dev/null
  sleep 1
  exit $1
}

checkEmptyListResponse () {
  case $1 in
    1) return 0;;
    0) killAgent 99;;
    *) killAgent $1;;
  esac
  return 33
}

showAgentMsg() {
  show_status $1 "$2"
  if test $1 -ne 0; then
    printf '%s' "${warn}"
    cat "${SSH_ERRLOG}"
    printf '%s' "${norm}"
    if test $1 -ne 2; then
      killAgent $1
    fi
    exit $1
  fi

  if test "x$3" != "x"; then
    printf '%s' "${done}"
    cat "$3"
    printf '%s' "${norm}"
  fi
  return 0
}

  eval `"${TEST_SSH_SSHAGENT}"` > /dev/null

  "${TEST_SSH_SSHADD}" -L >/dev/null; checkEmptyListResponse $?

  "${TEST_SSH_SSHADD}" "${identity_file}" 2> "${SSH_ERRLOG}" > "${SSH_REPLY}"; \
  showAgentMsg $? "  add identity ${extd}${SSH_CLIENTKEY}-${attn}${type}${norm} to agent ..."

  "${TEST_SSH_SSHADD}" -L 2> "${SSH_ERRLOG}" > "${SSH_REPLY}"; \
  retval=$?
  if test $retval -ne 0; then
    showAgentMsg ${retval}
  else
    printf "  ${done}-${norm} "
    if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
      printf '%s.......\n' "`cut -c -60 \"${SSH_REPLY}\"`"
    else
      cat "${SSH_REPLY}"
    fi
  fi

# TODO
# Note the current script run ssh with -i option,
# but ssh check existence of file and when file
# don't exit it is excluded from list of identity
# files. When the list is empty ssh will use
# default file names. To avoid this we will
# use /dev/null, until method runTest run ssh
# with -i option
#!!!    "use-only-key-from-agent" \
  runTest "${type}" \
    "/dev/null" \
    "key from agent ..." ||
  killAgent $?

  "${TEST_SSH_SSHADD}" -d "${identity_file}".pub \
    2> "${SSH_ERRLOG}" > "${SSH_REPLY}"; \
  showAgentMsg $? "  remove identity ${extd}${SSH_CLIENTKEY}-${attn}${type}${norm} from agent ..."

  "${TEST_SSH_SSHADD}" -L > /dev/null; checkEmptyListResponse $?

  killAgent 0
)
}


# ===

do_test () {
  retval=0
  if test "x${SSH_X509STORE_DISABLED}" = "xyes"; then
    echo "* ${extd}with x509 identity from ${attn}agent${norm}:"
  else
    echo "* ${extd}against ${attn}CACertificateFile${norm} and x509 identity from ${attn}agent${norm}:"
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
        testAgent || exit $?
      done
    done
  ); retval=$?
  killSSHdaemon
  return $retval
}
