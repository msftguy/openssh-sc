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
# DESCRIPTION: Create a new certificate authority config and database.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/1-cre_cadb.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"


# ===
# args:
#   $1 - type
echo_CA_common_options () {
cat <<EOF
# Where everything is kept:
dir             = ${SSH_CAROOT}

certs           = \$dir/crt             # Where the issued certs are kept
crl_dir         = \$dir/crl             # Where the issued crl are kept
database        = \$dir/index-$1.txt       # database index file.
new_certs_dir   = \$dir/newcerts        # default place for new certs.
serial          = \$dir/serial          # The current serial number

#x509_extensions = usr_cert            # The default extentions to add to the cert
default_days    = ${SSH_CACERTDAYS}                   # how long to certify for
default_crl_days= 30                   # how long before next CRL
policy          = policy_match

# print options (internal use)
name_opt        = oneline,-space_eq,-esc_msb # print fine UTF-8
cert_opt        = compatible

EOF
}


# ===
# args:
#   none
echo_CA_ocsp_options () {
if test "x$SSH_OCSP" = "xyes"; then
cat << EOF

# OCSP Validator(Responder) URI
# Since OpenSSL OCSP responder support only one issuer certificate
# we should setup for the test cases many responders - each certificate
# type with responder on different port.
EOF
  printf "authorityInfoAccess = "
(
  port=${SSH_VA_BASEPORT}
  for DIGEST in ${RSA_DIGEST_LIST}; do
    printf "OCSP;URI:http://${SSHD_LISTENADDRESS}:${port},"
    port=`expr ${port} + 1`
  done
    printf "OCSP;URI:http://${SSHD_LISTENADDRESS}:${port}"
)
fi
}


# ===
cre_config () {
cat << EOF > "$1"
[ ca ]
#md5 is not allowed in FIPSmode
#default_ca              = CA_OpenSSH_rsa_md5
default_ca              = CA_OpenSSH_rsa_sha1


# For the CA policy
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ ca_policy_match ]
countryName             = match
stateOrProvinceName     = match
localityName            = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional


[ req ]
default_bits            = 1024
distinguished_name      = req_distinguished_name
attributes              = req_attributes
#prompt                  = no
#string_mask             = MASK: <unsigned long> | nombstr | pkix | utf8only | default(=0xFFFFFFFFL)
#utf8                    = yes

# The extensions to add to a certificate request:
#???req_extensions          = usr_cert


[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = $SSH_DN_C
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = $SSH_DN_ST

localityName                    = Locality Name (eg, city)
localityName_default            = $SSH_DN_L

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = $SSH_DN_O

0.organizationalUnitName          = Organizational Unit1 Name (eg, section1 - optional)
0.organizationalUnitName_default  = ${SSH_DN_OU}-1

1.organizationalUnitName          = Organizational Unit2 Name (eg, section2 - optional)
1.organizationalUnitName_default  = ${SSH_DN_OU}-2

2.organizationalUnitName          = Organizational Unit3 Name (eg, section3 - optional)
2.organizationalUnitName_default  = ${SSH_DN_OU}-3

commonName                      = Common Name (eg, YOUR name)
commonName_min                  = 2
commonName_max                  = 64

emailAddress                    = Email Address (optional)
emailAddress_max                = 40
emailAddress_default            = $SSH_DN_EM


[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20


[ ca_root_cert ]
# PKIX recommendation.

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
# Since we generate OpenSSH test CA we can comment next line.
basicConstraints=CA:true

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated OpenSSH Test CA Certificate"

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# Since we verify CRL signatures cRLSign must present
keyUsage = keyCertSign, cRLSign

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid:always,issuer:always

[ ca_cert ]
# PKIX recommendation.

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
# Since we generate OpenSSH test CA we can comment next line.
basicConstraints=CA:true

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated OpenSSH Test CA Certificate"

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# Since we verify CRL signatures cRLSign must present
keyUsage = keyCertSign, cRLSign

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid:always,issuer:always

# To test CRL presence this extension should exist
crlDistributionPoints = URI:attribute_only_exist
EOF


# X.509 extensions: SSH client certificates
cat << EOF >> "$1"


[ usr_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:FALSE
nsCertType                      = client, email

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated OpenSSH Test Client Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always
EOF

echo_CA_ocsp_options >> "$1"


# X.509 extensions: SSH server certificates
cat << EOF >> "$1"


[ srv_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:FALSE

# To test OpenSSH hostbased authentication we need
# following certificate purposes:
nsCertType                      = server,client
# Normal for server certificate is:
#nsCertType                      = server
# but in last case me must disable check of certificate purposes
# in sshd_config otherwise hostbased fail.

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated OpenSSH Test Server Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always

# Some SSH clients require server certificate to contain
# correct alternate name of type DNS (FQDN)
subjectAltName = DNS:localhost
EOF

echo_CA_ocsp_options >> "$1"


# X.509 extensions: OCSP Validator certificates
if test "x$SSH_OCSP" = "xyes"; then
cat << EOF >> "$1"


[ ocsp_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:FALSE

# Normal for validator certificate is:
nsCertType                      = objsign

# This is typical in keyUsage for a validator certificate.
keyUsage = nonRepudiation, digitalSignature

# This should present for a validator certificate.
extendedKeyUsage = OCSPSigning

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated OpenSSH Test OCSP Responder Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always
EOF
fi


cat << EOF >> "$1"


[ CA_OpenSSH_root ]
# Where everything is kept:
dir             = ${SSH_CAROOT}

certs           = \$dir/crt             # Where the issued certs are kept
crl_dir         = \$dir/crl             # Where the issued crl are kept
database        = \$dir/index-root.txt  # database index file.
new_certs_dir   = \$dir/newcerts        # default place for new certs.
serial          = \$dir/serial          # The current serial number

#x509_extensions = usr_cert            # The default extentions to add to the cert
default_days    = ${SSH_CACERTDAYS}                   # how long to certify for
default_crl_days= 30                   # how long before next CRL
policy          = ca_policy_match

# print options (internal use)
name_opt        = oneline,-space_eq,-esc_msb # print fine UTF-8
cert_opt        = compatible


# which md to use:
default_md      = sha1

# The private key (!)
private_key     = "${SSH_CAKEYDIR}/${CAKEY_PREFIX}-root0.key"

#The CA certificate (!)
certificate     = "${SSH_CACERTDIR}/${CAKEY_PREFIX}-root0.crt.pem"
EOF


for DIGEST in ${RSA_DIGEST_LIST}; do
( cat << EOF


[ CA_OpenSSH_rsa_${DIGEST} ]
EOF
  echo_CA_common_options "rsa_${DIGEST}"
  cat << EOF
# which md to use:
default_md      = ${DIGEST}

# The private key (!)
private_key     = "${SSH_CAKEYDIR}/${CAKEY_PREFIX}-rsa.key"

#The CA certificate  (!)
certificate     = "${SSH_CACERTDIR}/${CAKEY_PREFIX}-rsa_${DIGEST}.crt.pem"
EOF
) >> "$1"
done

( cat << EOF


[ CA_OpenSSH_dsa ]
EOF
  echo_CA_common_options "dsa"
  cat << EOF
# which md to use:
default_md      = sha1

# The private key (!)
private_key     = "${SSH_CAKEYDIR}/${CAKEY_PREFIX}-dsa.key"

#The CA certificate  (!)
certificate     = "${SSH_CACERTDIR}/${CAKEY_PREFIX}-dsa.crt.pem"
EOF
) >> "$1"
}


# ===
cre_db () {
(
  var="${SSH_CAROOT}"

  if test ! -d "$var"; then
    mkdir -p "$var" || exit $?
  else
    count=`getNextDirName "${var}"` || exit $?
    if test -d "${var}"; then
      printf '%s' "saving old directoty as ${attn}${var}.${warn}${count}${norm} ... "
      mv "${var}" "${var}.${count}"; show_status $? || exit $?
    fi
  fi

  mkdir -p "$var" &&
  mkdir "$var/crt" &&
  mkdir "$var/crl" ||
  exit $?

  create_empty_file "$var/index-root.txt" || exit $?

  for type in ${SSH_SIGN_TYPES}; do
    create_empty_file "$var/index-${type}.txt" || exit $?
  done

  mkdir "$var/newcerts" &&
  echo '200402160906000001' > "$var/serial"
)
}


# ===

cre_config "${TMPDIR}/${CACONFIG}" &&
cre_db &&
update_file "${TMPDIR}/${CACONFIG}" "${SSH_CACFGFILE}"; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}TEST${norm} ${attn}Certificate Authority Database${norm}"
