#!/usr/bin/env bash

# https://gist.github.com/dhoffi/4ce57bdd8d8b11628bca4715b18aeecf

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

destFolder="certs"
oldFolder="${destFolder}/old"
filepostfix=$(date +_%Y%m%d_%H%M%S)

function usage() {
    echo "usage: "
    echo "       self-signed-cert:      ${0##*/}        some.domain.or.ip:optionalPort [aliasIP(s)_or_Domain(s)]"
    echo "       rootca:                ${0##*/} rootca some.domain.or.ip:optionalPort [aliasIP(s)_or_Domain(s)]"
    echo "       cert signed by rootca: ${0##*/} cert   some.domain.or.ip:optionalPort [aliasIP(s)_or_Domain(s)]"
    echo "            (root ca cert and root ca key exptected to be in ${destFolder} named rootca.cert and rootca.key)"
    echo "  flags:"
    echo "         -f   --filebasename <outFilenameBase>          (without any postfix)"
    echo "         -d   --destfolder <destfolder>"
    echo "     for 'cert' specify name of rootCA file in certs/:"
    echo "         -ca  --cafilebasename <path/caFilenameBase>    (without any postfix like .cert or .key postfix)"
    exit 1
}

finish() {
    set +x
}
trap finish EXIT

function valid_fqdn_or_wildcardDomain() {
    local domain="$1"
    local allowSimpleFQDNs="true" # "false"
    if [[ $domain = "localhost" ]]; then
        return 0
    fi
    if [[ $domain =~ ^(\*\.)?[0-9]{1,}\.[0-9]{1,}(\.([0-9]{1,}))*(:[0-9]{4,5})?$ ]]; then 
        return 1 # this too much looks like a mislead IP
    fi
    if [[ $allowSimpleFQDNs = "true" ]]; then
        if [[ $domain =~ ^(\*\.)?[a-z0-9-]{1,}(\.([a-z0-9-]{1,}))*(:[0-9]{4,5})?$ ]]; then 
            return 0
        else
            return 1
        fi
    else
        if [[ $domain =~ ^(\*\.)?[a-z0-9-]{1,}\.[a-z0-9-]{1,}(\.([a-z0-9-]{1,}))*(:[0-9]{4,5})?$ ]]; then 
            return 0
        else
            return 1
        fi
    fi
}

function valid_ip() {
    local ip="$1"
    local stat=1
    local pureip
    local ipnr
    local port

    if [[ $ip =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:([0-9]*))?$ ]]; then
        if [[ ${BASH_REMATCH[2]} = ":" ]]; then
            >&2 echo "ERROR: IP with colon but no port: $ip"
            return 1
        fi
        pureip=${BASH_REMATCH[1]}
        port=${BASH_REMATCH[3]}
        OLD_IFS=$IFS
        IFS='.'
        ipnr=($pureip)
        IFS=$OLD_IFS
        if [[ -n "$ip" && ${ipnr[0]} -le 255 && ${ipnr[1]} -le 255 && ${ipnr[2]} -le 255 && ${ipnr[3]} -le 255 ]]; then
            stat=0
        else
            >&2 echo "ERROR: IP part > 255 in $ip"
        fi
        if [[ $stat -eq 0 && -n "$port" ]]; then
            stat=1
            if [[ $port -gt 1024 && $port -le 65535 ]]; then
                stat=0
            else
                >&2 echo "ERROR: IP port not in range 1025-65535 in $ip"
            fi
        fi
    fi
    return $stat
}

rootcaArg="false"
certArg="false"
if [ -z "$1" ] || [ $# -lt 1 ]; then usage ; fi
for i in {1..3}; do
    if [ "$1" = "-f" ] || [ "$1" = "--filebasename" ]; then
        if [ -z "$2" ]; then >&2 echo "no filename given"; usage ; fi
        flagFileBasename="$2"
        shift ; shift 
        if [ -z "$1" ] || [ $# -lt 1 ]; then usage ; fi
    fi
    if [ "$1" = "-d" ] || [ "$1" = "--destfolder" ]; then
        if [ -z "$2" ]; then >&2 echo "no destfolder given"; usage ; fi
        destFolder="$2"
        shift ; shift 
        if [ -z "$1" ] || [ $# -lt 1 ]; then usage ; fi
    fi
    if [ "$1" = "-ca" ] || [ "$1" = "--cafilebasename" ]; then
        if [ -z "$2" ]; then >&2 echo "no cafilebasename given"; usage ; fi
        flagCaFileBasename="$2"
        shift ; shift 
        if [ -z "$1" ] || [ $# -lt 1 ]; then usage ; fi
    fi
done
if [ "$1" = "rootca" ]; then
    rootcaArg="true"
    shift
    if [ -z "$1" ] || [ $# -lt 1 ]; then usage ; fi
elif [ "$1" = "cert" ]; then
    certArg="true"
    shift
    if [ -z "$1" ] || [ $# -lt 1 ]; then usage ; fi
fi

if [[ "${rootcaArg}" = "true" ]]; then
    rootcaBasicConstraints="\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nissuerAltName=URI:Hoffi"
else
    rootcaBasicConstraints=""
fi

# BEWARE! ports are not allowed in subjectAltName aliases!
# the CN(=commonName also ALWAYS should be included in the SAN(=SubjectAlternateNames))
# subjectAltName="-reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf \"[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com,IP:10.0.2.240\"))"
# maybe bad idea but we use one param loop to:
#   a) check given parameters for validity (valid ip or domain) and
#   b) add them to subjectAltName openssl cmd part used later
subjectAltName="-reqexts MYPART -config <(cat /etc/ssl/openssl.cnf <(printf \"[MYPART]\nsubjectAltName="
checksFailed="false"
first="true"
for arg in "$@"; do
    valid_ip "$arg"
    isValidIp=$?
    if [[ "${rootcaArg}" = "true" ]]; then
        isValidDN=0
    else
        valid_fqdn_or_wildcardDomain "$arg"
        isValidDN=$?
    fi
    if [[ ! isValidIp -eq 0 && ! isValidDN -eq 0 ]]; then
            checksFailedMessage+="$arg is neither a valid domain nor IP\n"
            checksFailed="true"
    else
        if [[ "$first" != "true" ]]; then # if more than one subjectAltName separate by ','
            subjectAltName+=","
        else
            first="false"
        fi
        if [[ isValidIp -eq 0 ]]; then
            subjectAltName+="IP:$arg"
        else
            subjectAltName+="DNS:$arg"
        fi
    fi
done
subjectAltName+="${rootcaBasicConstraints}\"))"

if [[ "$checksFailed" = "true" ]]; then
    >&2 echo -e "$checksFailedMessage"
    usage
fi

commonName="$1"
if [ -z "$flagFileBasename" ]; then
    filebasename=${commonName//[-.:]/_}
    filebasename=${filebasename#\*_} # strip potential wildcard prefix
else
    filebasename="$flagFileBasename"
fi
if [ "$rootcaArg" = "true" ]; then
    if [ -z "$flagFileBasename" ]; then
        filebasename="rootca";
    else
        filebasename="$flagFileBasename"
    fi
fi
if [[ "${rootcaArg}" = "true" ]]; then
    # if we do a rootca we make sure that it contains something like root_ca in it somewhere
    if [[ ! "$(echo "$commonName" | tr '[:upper:]' '[:lower:]')" =~ root.?ca ]]; then
        commonName="rootCA_${commonName#\*\.}" # prefix with rootCA_ and removing wildcard prefix if present
    fi
    if [[ ! "$(echo "$filebasename" | tr '[:upper:]' '[:lower:]')" =~ root.?ca ]]; then
        filebasename="rootCA_${filebasename#\*\.}" # prefix with rootCA_ and removing wildcard prefix if present
    fi
fi

keyFilename="${filebasename}.key"
csrFilename="${filebasename}.csr"
certFilename="${filebasename}.cert"
pemFilename="${filebasename}.pem" # readable .pem file (may contain multiple certs and keys)
if [[ "${certArg}" = "true" ]]; then
    if [ -z "$flagCaFileBasename" ]; then
        cakeyFilename="${destFolder}/rootca.key"   # on creating rootca same as $keyFilename
        cacertFilename="${destFolder}/rootca.cert" # on creating rootca same as $certFilename
    else
        cakeyFilename="${flagCaFileBasename}.key"
        cacertFilename="${flagCaFileBasename}.cert"
    fi
fi
set -e

# backup existing files so not to overwrite them
mkdir -p "$destFolder"
mkdir -p "$oldFolder"
allFiles=("$keyFilename" "$csrFilename" "$certFilename" "$pemFilename")
for f in "${allFiles[@]}"; do
    if [[ -f "$destFolder/$f" ]]; then mv "$destFolder/$f" "$oldFolder/$f$filepostfix"; fi
done

country="DE"
state="Bavaria"
location="Munich"
organization="Personal Security"
organizationalUnit="IT Department"
email="test@gmail.com"
bits=2048
days=730 # two years
encryptPrivateKey="-nodes" # define empty to encrypt private keys

# commands based on
# https://bosh.io/docs/director-certs-openssl/
# and
# https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309

#### create rootCa (cert signing request for rootCA) with a newly generated private key ALL IN ONE COMMAND
#### as this kind of rootCA is a self contained self-signed cert to be doployed somewhere
#### and seldomly will be used for signing other certs, we give it THE CN(=commonName), etc. and aliasNames(=subjectAltName(s))
#### if this should just be a rootCA they will be in it also ... but who cares ...
s="openssl req -newkey rsa:$bits $encryptPrivateKey -keyout %s -out %s -subj \"/emailAddress=%s/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s\" %s\n"
csrCmd=$(printf "$s" "$destFolder/$keyFilename" "$destFolder/$csrFilename" "$email" "$country" "$state" "$location" "$organization" "$organizationalUnit" "$commonName" "$subjectAltName")
echo $csrCmd
eval $csrCmd
echo
### sign the certificate signing request (csr) and produce a .cert
    # Extensions in certificates are NOT transferred to certificate requests and vice versa. So we have to give $subjectAltName of the csr again
    # unfortunately the openssl options have different names than on creating the csr
    # so it should not be "-reqexts <sectionName> -config <xyz.cnf>" but on signing the cert it is "-extension <sectionName> -extfile <xyz.cnf>"
if [[ "${certArg}" = "false" ]]; then
    ### we want to create either a self-signed cert or the rootCa cert
    s="openssl x509 -req -in %s -signkey %s -out %s -days $days %s\n"
    certCmd=$(printf "$s" "$destFolder/$csrFilename" "$destFolder/$keyFilename" "$destFolder/$certFilename" "${subjectAltName//-reqexts MYPART -config/-extensions MYPART -extfile}")
    echo $certCmd
    eval $certCmd
    echo
elif [[ "${certArg}" = "true" ]]; then
    ### we expect rootca.key and rootca.cert files to be in $destFolder
    ### or having been given via -ca or --cafilebasename flags
    ### and use these to sign the certificate signing request (csr)
    s="openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days $days %s\n"
    certCmd=$(printf "$s" "$destFolder/${csrFilename}" "$cacertFilename" "$cakeyFilename" "$destFolder/${certFilename}" "${subjectAltName//-reqexts MYPART -config/-extensions MYPART -extfile}")
    echo $certCmd
    eval $certCmd
    echo
fi
### optional also produce a pem file of the cert (in our case same as .cert but with .pem postfix)
s="openssl x509 -in %s -out %s" #  -inform der
pemCmd=$(printf "$s" "$destFolder/$certFilename" "$destFolder/$pemFilename")
echo $pemCmd
eval $pemCmd
echo

### output information of our results (csr and cert)
checkCsrCmd="openssl req -in $destFolder/$csrFilename -text -noout"
echo "==============================================================="
echo "checkCsr: $checkCsrCmd"
echo "==============================================================="
eval $checkCsrCmd
echo ""
checkCertCmd="openssl x509 -text -noout -in $destFolder/$certFilename -certopt no_header,no_pubkey,no_sigdump"
echo "========================================================================================================="
echo "checkCert: $checkCertCmd"
echo "========================================================================================================="
eval $checkCertCmd

ls -la $destFolder

# openssl req -x509 -days 365 -newkey rsa:2048 -nodes -keyout example.key -out example.csr -subj \"/C=GB/ST=London/L=London/O=Globy/OU=IT Department/CN=example.com\"
# -x509    = output a x509 structure (= self-signed certificate) instead of a certificate signing request (= .csr)
# -days    = validity period of the certificate in days (only effective in combination with -x509 or x509 command)
# -newkey  = generate a new private key along with the certificate and do not take an existing one via -key server.key
#            use rsa for the private key with a length of 2048 bit
# -nodes   = do not des encrypt the private key but leave it plain text
# -keyout  = file to write the private key to usually the filename has no suffix at all or .key
# -out     = filename of the Certificate signing request usually suffixed .csr
#            the .csr is used to get signed by a CA (Certification Authority) like verizon or cacert.org
#
# you can also create a config file (e.g. req.conf) with all needed information and tell openssl to use it
# [req]
# distinguished_name = req_distinguished_name
# x509_extensions = v3_req
# prompt = no
# [req_distinguished_name]
# C = DE
# ST = Bavaria
# L = Munich
# O = Personal Security
# OU = IT Department
# CN = www.company.com
# emailAddress  = test@test.com
# [v3_req]
# keyUsage = keyEncipherment, dataEncipherment
# extendedKeyUsage = serverAuth
# subjectAltName = @alt_names
# [alt_names]
# DNS.1 = www.company.com
# DNS.2 = company.com
# DNS.3 = company.net
#
# and use a command like the following to use the config file:
#    openssl req -x509 -days 365 -sha256 -newkey rsa:2048 -nodes -keyout cert.key -out cert.csr -config req.cnf -extensions 'v3_req'
# please notice: to generate a .csr do NOT pass -x509 to openssl, to create a self-signed certificate do pass -x509
#
# on terminal
# print a self-signed certificate with:
#    openssl x509 -in certificate.crt -text -noout
# print a signing request with:
#     openssl req  -in certificate.csr -text -noout
#
# to create a self-signed certificate from a .csr:
#    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
