#! /bin/sh
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
# DESCRIPTION: Create "Test Certificate Authority" CRLs.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/4-cre_crls.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"


OPENSSH_LOG="$CWD/openssh_ca-4.log"
create_empty_file .delmy &&
update_file .delmy "$OPENSSH_LOG" > /dev/null || exit $?


# ===
cre_crlfile() {
(
  type="$1"

  cd "${SSH_CACRLDIR}" || exit $?

  FILE="${CAKEY_PREFIX}-${type}.crl.pem"

  printf '%s' "- ${attn}${type}${norm} certificates"
  ${OPENSSL} ca \
    -config "${SSH_CACFGFILE}" \
    -name "CA_OpenSSH_${type}" \
    -passin pass:${KEY_PASS} \
    -gencrl \
    -out "${FILE}" \
    2>> "$OPENSSH_LOG" \
  ; show_status $? || exit $?

  HASH=`${OPENSSL} crl -out /dev/null -in "${FILE}" -hash 2>> "$OPENSSH_LOG"` || exit $?

  NAME=`getNextFreeName "${HASH}.r"` || exit $?

  ln -s "${FILE}" "${NAME}"
  #link might never fail :-(
  test -h "${NAME}"
)
}


# ===
cre_crlindir () {
  echo "=== create a new CRL ===" >> "$OPENSSH_LOG"
  rm -f "${SSH_CACRLDIR}"/* 2>/dev/null

  printf '%s\n' "creating ${extd}CA CRL file${norm} for ..."
  for type in ${SSH_SIGN_TYPES}; do
    cre_crlfile "${type}" || return $?
  done

  return 0
}


# ===
cre_CAcrlfile () {
(
  crlfile="${SSH_CAROOT}/${CACRLFILE}"

  create_empty_file "$crlfile"-t &&
  for type in $SSH_SIGN_TYPES; do
    ( $OPENSSL crl \
      -in "$SSH_CACRLDIR/${CAKEY_PREFIX}-${type}.crl.pem" \
      -text \
      2>> "$OPENSSH_LOG" \
      && echo && echo
    ) >> "$crlfile"-t || exit $?
  done

  mv "$crlfile"-t "$crlfile"
)
}


# ===
cre_all () {
  cre_crlindir || return $?

  printf '%s' "creating ${extd}CA CRL ${attn}common${norm} ${extd}file${norm} ..."
  cre_CAcrlfile; show_status $?
}


# ===
cre_all; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}TEST${norm} ${attn}Certificate Authority${norm} CRL files"
