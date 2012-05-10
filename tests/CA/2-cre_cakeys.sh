#! /bin/sh
# Copyright (c) 2002-2006,2011 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Create "Test Certificate Authority" private keys and certificates.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/2-cre_cakeys.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"


OPENSSH_LOG="$CWD/openssh_ca-2.log"
create_empty_file .delmy &&
update_file .delmy "$OPENSSH_LOG" > /dev/null || exit $?


# ===
echo_SSH_CA_DN () {
cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
$SSH_DN_OU
$SSH_DN_OU $1 keys
.
OpenSSH $1 TestCA key
.
.
EOF
}


# ===
echo_SSH_CAROOT_DN () {
cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
$SSH_DN_OU
$SSH_DN_OU level $1
.
OpenSSH TestCA level $1
.
EOF
}


# ===
#args:
#  $1 - rsa keyfile
gen_rsa_key () {
  RSA_OPT=
  if test -f /etc/random-seed; then
    RSA_OPT="$RSA_OPT -rand /etc/random-seed"
  fi

  rm -f "$1" 2>/dev/null

  if $openssl_nopkcs8_keys; then
    rm -f "$1"-trad 2>/dev/null
    $OPENSSL genrsa $RSA_OPT \
      -out "$1"-trad 1024 \
      2>> "$OPENSSH_LOG" &&
    $OPENSSL pkcs8 -topk8 \
      -in "$1"-trad \
      -out "$1" -passout pass:$KEY_PASS \
      -v1 PBE-SHA1-3DES \
      2>> "$OPENSSH_LOG" &&
    rm "$1"-trad
  else
    RSA_OPT="$RSA_OPT -des3"
    $OPENSSL genrsa $RSA_OPT \
      -passout pass:$KEY_PASS \
      -out "$1" 1024 \
      2>> "$OPENSSH_LOG"
  fi
}


# ===
cre_root () {
  gen_rsa_key "$TMPDIR/$CAKEY_PREFIX"-root0.key \
  ; show_status $? "generating ${extd}TEST ROOT CA${norm} ${attn}rsa${norm} private key" \
  || return $?

  echo_SSH_CAROOT_DN "0" | \
  $OPENSSL req \
    -new -x509 \
    -config "$SSH_CACFGFILE" \
    $SSH_DN_UTF8_FLAG \
    -days $SSH_CACERTDAYS \
    -passin pass:${KEY_PASS} \
    -key "$TMPDIR/${CAKEY_PREFIX}-root0.key" \
    -sha1 \
    -out "$TMPDIR/${CAKEY_PREFIX}-root0.crt" \
    -extensions ca_root_cert \
    2>> "$OPENSSH_LOG" \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}root${norm} certificate" \
  || return $?

  F="$CAKEY_PREFIX"-root0.key
  update_file "$TMPDIR/$F" "$SSH_CAKEYDIR/$F" &&
  chmod 400 "$SSH_CAKEYDIR/$F" || return $?

  F="$CAKEY_PREFIX"-root0.crt
  update_file "$TMPDIR/$F" "$SSH_CACERTDIR/$F".pem
}


# ===
gen_rsa () {
  gen_rsa_key "$TMPDIR/$CAKEY_PREFIX"-rsa.key \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}rsa${norm} private key"
}


# ===
#args:
#  $1 - dsa keyfile
#  $2 - dsa parameter file
gen_dsa_key () {
  DSA_OPT=
  if test -f /etc/random-seed; then
    DSA_OPT="$DSA_OPT -rand /etc/random-seed"
  fi

  rm -f "$1" 2>/dev/null

  if $openssl_nopkcs8_keys; then
    rm -f "$1"-trad 2>/dev/null &&
    $OPENSSL gendsa $DSA_OPT \
      -out "$1"-trad \
      "$2" \
      2>> "$OPENSSH_LOG" &&
    $OPENSSL pkcs8 -topk8 \
      -in "$1"-trad \
      -out "$1" -passout pass:$KEY_PASS \
      -v1 PBE-SHA1-3DES \
      2>> "$OPENSSH_LOG" &&
    rm "$1"-trad
  else
    DSA_OPT="$DSA_OPT -des3"
    $OPENSSL gendsa $DSA_OPT \
      -passout pass:$KEY_PASS \
      -out "$1" \
      "$2" \
      2>> "$OPENSSH_LOG"
  fi
}


# ===
gen_dsa () {
  DSA_OPT=
  if test -f /etc/random-seed; then
    DSA_OPT="$DSA_OPT -rand /etc/random-seed"
  fi

  rm -f "$TMPDIR/$CAKEY_PREFIX-dsa.prm" 2>/dev/null
  $OPENSSL dsaparam $DSA_OPT \
    -out "$TMPDIR/$CAKEY_PREFIX"-dsa.prm 1024\
    2>> "$OPENSSH_LOG";\
  show_status $? "generating ${extd}DSA parameter file${norm}" \
  || return $?

  gen_dsa_key \
    "$TMPDIR/$CAKEY_PREFIX"-dsa.key \
    "$TMPDIR/$CAKEY_PREFIX"-dsa.prm \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}dsa${norm} private key"
}


# ===
cre_crt () {
for type in $SSH_SIGN_TYPES; do
  rm -f "$TMPDIR/$CAKEY_PREFIX"-${type}.crt 2>/dev/null

  case $type in
      *rsa*) keyfile="$TMPDIR/$CAKEY_PREFIX"-rsa.key;;
      *dsa*) keyfile="$TMPDIR/$CAKEY_PREFIX"-dsa.key;;
      *) return 99;;
  esac

  echo_SSH_CA_DN "$type" |
  $OPENSSL req \
    -new \
    -config "$SSH_CACFGFILE" \
    $SSH_DN_UTF8_FLAG \
    -key "$keyfile" \
    -passin pass:$KEY_PASS \
    -out "$TMPDIR/${CAKEY_PREFIX}-${type}".csr \
    2>> "$OPENSSH_LOG" \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}${type}${norm} request" \
  || return $?

  $OPENSSL ca \
    -config "$SSH_CACFGFILE" \
    -batch \
    -in "$TMPDIR/${CAKEY_PREFIX}-${type}".csr \
    -name "CA_OpenSSH_root" \
    -passin pass:$KEY_PASS \
    -out "$TMPDIR/${CAKEY_PREFIX}-${type}".crt \
    -extensions ca_cert \
    2>> "$OPENSSH_LOG" \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}${type}${norm} certificate" || \
  { retval=$?
    printf '%s' "${warn}"
    grep 'ERROR:' "$OPENSSH_LOG"
    printf '%s' "${norm}"
    rm -f "$TMPDIR/${CAKEY_PREFIX}-${type}".csr
    rm -f "$TMPDIR/${CAKEY_PREFIX}-${type}".crt
    return $retval
  }

  sync
  $OPENSSL verify \
    -CAfile "$SSH_CACERTDIR/$CAKEY_PREFIX"-root0.crt.pem \
    "$TMPDIR/${CAKEY_PREFIX}-${type}".crt \
  ; retval=$?
  # exit code always is 0 :(

  rm -f "$TMPDIR/${CAKEY_PREFIX}-${type}".csr

  test $retval -ne 0 && return $retval
done
  return 0
}


# ===
crt2bundle () {
(
  val="$1"
  test -z "${val}" && { echo ${warn}missing DN${norm} >&2; return 1; }

  echo
  echo ${val}
  echo ${val} | sed -e 's/./=/g'
  $OPENSSL x509 -inform PEM -in "${2}" -fingerprint -noout || exit $?
  echo PEM data:
  $OPENSSL x509 -inform PEM -in "${2}" -trustout           || exit $?
  echo Certificate Ingredients:
  $OPENSSL x509 -inform PEM -in "${2}" -text -noout        || exit $?

  exit 0
)
}


# ===
cre_dirs () {
  for D in \
    "$SSH_CAROOT" \
    "$SSH_CAKEYDIR" \
    "$SSH_CACERTDIR" \
  ; do
    if test ! -d "$D"; then
      mkdir -p "$D" || return $?
    fi
  done
  chmod 700 "$SSH_CAKEYDIR"
}


install () {
(
  update_file "$TMPDIR/${CAKEY_PREFIX}-dsa.prm" "$SSH_CAROOT/${CAKEY_PREFIX}-dsa.prm" || exit $?

  for type in rsa dsa; do
    F="${CAKEY_PREFIX}-${type}.key"
    update_file "${TMPDIR}/${F}" "${SSH_CAKEYDIR}/${F}" &&
    chmod 400 "${SSH_CAKEYDIR}/${F}" || exit $?
  done

  for type in ${SSH_SIGN_TYPES}; do
    F="${CAKEY_PREFIX}-${type}.crt"
    update_file "${TMPDIR}/${F}" "${SSH_CACERTDIR}/${F}.pem" || exit $?
  done

  create_empty_file "${TMPDIR}/${CACERTFILE}" &&
  for level in 0; do
    F="$SSH_CACERTDIR/$CAKEY_PREFIX"-root${level}.crt.pem
    crt2bundle "$SSH_DN_O level $level" "$F" >> "$TMPDIR/$CACERTFILE" || exit $?
  done
  for type in ${SSH_SIGN_TYPES}; do
    F="${SSH_CACERTDIR}/${CAKEY_PREFIX}-${type}.crt.pem"
    crt2bundle "${SSH_DN_O}-${type}" "${F}" >> "${TMPDIR}/${CACERTFILE}" || exit $?
  done

  update_file "${TMPDIR}/${CACERTFILE}" "${SSH_CAROOT}/${CACERTFILE}"
)
}


# ===
cre_hash_link () {
(
#option -noout problem:
#exit code from .../openssl ... -noout ... is sometime nonzero !!!
#might only by .../openssl x509 ... -noout ... exit code is zero
#sample:
#a) exit code is one - INCORRECT
#  .../openssl crl -in a_crl_file  -hash -noout
#b) exit code is zero - correct
#  .../openssl crl -in a_crl_file  -hash -out /dev/null
#
#work around might is to use -out /dev/null :-/
  HASH=`$OPENSSL x509 -in "$1" -noout -hash` || exit $?
  NAME=`getNextFreeName ${HASH}.`            || exit $?

  echo "creating link ${attn}${NAME}${norm} to ${attn}$1${norm}"
  rm -f "${NAME}" &&
  ln -s "$1" "${NAME}" || exit $?
  #link might never fail ;-(
  test -h "${NAME}"
)
}


cre_hashs () {
#(!) openssl script "c_rehash" is missing in some installations :-(
#  c_rehash "${SSH_CACERTDIR}"
(
  cd "${SSH_CACERTDIR}" || exit $?

  for F in [0-9a-f]*.[0-9]; do
    # we must use test -L, but on ?-OSes ... :-(
    if test -h "$F"; then
      rm -f "$F" || exit $?
    fi
  done

  for level in 0; do
    cre_hash_link "${CAKEY_PREFIX}-root${level}.crt.pem" || exit $?
  done

  for type in ${SSH_SIGN_TYPES}; do
    cre_hash_link "${CAKEY_PREFIX}-${type}.crt.pem" || exit $?
  done

  exit 0
)
}


# ===

cre_dirs &&
cre_root &&
gen_rsa &&
gen_dsa &&
cre_crt &&
install &&
cre_hashs; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}TEST${norm} ${attn}Certificate Authority${norm}"
echo "${warn}password for all private keys is ${attn}${KEY_PASS}${norm}"
exit $retval
