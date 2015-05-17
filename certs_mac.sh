
#------------------------------------------------------------------------------------------------------------------------
#======================================= COLORS =========================================================================
#------------------------------------------------------------------------------------------------------------------------
# from: https://gist.github.com/ziyaddin/8957973
RCol='\033[0m'    # Text Reset

# Regular           Bold                Underline           High Intensity      BoldHigh Intens     Background          High Intensity Backgrounds
Bla='\033[0;30m';     BBla='\033[1;30m';    UBla='\033[4;30m';    IBla='\033[0;90m';    BIBla='\033[1;90m';   On_Bla='\033[40m';    On_IBla='\033[0;100m';
Red='\033[0;31m';     BRed='\033[1;31m';    URed='\033[4;31m';    IRed='\033[0;91m';    BIRed='\033[1;91m';   On_Red='\033[41m';    On_IRed='\033[0;101m';
Gre='\033[0;32m';     BGre='\033[1;32m';    UGre='\033[4;32m';    IGre='\033[0;92m';    BIGre='\033[1;92m';   On_Gre='\033[42m';    On_IGre='\033[0;102m';
Yel='\033[0;33m';     BYel='\033[1;33m';    UYel='\033[4;33m';    IYel='\033[0;93m';    BIYel='\033[1;93m';   On_Yel='\033[43m';    On_IYel='\033[0;103m';
Blu='\033[0;34m';     BBlu='\033[1;34m';    UBlu='\033[4;34m';    IBlu='\033[0;94m';    BIBlu='\033[1;94m';   On_Blu='\033[44m';    On_IBlu='\033[0;104m';
Pur='\033[0;35m';     BPur='\033[1;35m';    UPur='\033[4;35m';    IPur='\033[0;95m';    BIPur='\033[1;95m';   On_Pur='\033[45m';    On_IPur='\033[0;105m';
Cya='\033[0;36m';     BCya='\033[1;36m';    UCya='\033[4;36m';    ICya='\033[0;96m';    BICya='\033[1;96m';   On_Cya='\033[46m';    On_ICya='\033[0;106m';
Whi='\033[0;37m';     BWhi='\033[1;37m';    UWhi='\033[4;37m';    IWhi='\033[0;97m';    BIWhi='\033[1;97m';   On_Whi='\033[47m';    On_IWhi='\033[0;107m';

int_regex='^[0-9]+$'

# Helpers

info(){
echo -en "${BBlu}info :  ${RCol}"
echo -e $1;
}
ok(){
echo -en "${BGre}ok   :  ${RCol}"
echo -e $1;
}
err(){
echo -en "\n${BRed}error:  ${RCol}"
echo -e "$1 --> abort"  >&2; exit 1
}
#------------------------------------------------------------------------------------------------------------------------
#======================================= ROOT ===========================================================================
#------------------------------------------------------------------------------------------------------------------------
do_root_create(){
##create key
info "create root key";
echo -n "Please specify the keysize: "
read keysize
if ! [[ $keysize =~ $int_regex ]] ; then
  err "Your keysize is not a number --> abort"
fi
echo -n "Please specify the name of the keyfile (without ending): "
read name
root_key=root_certs/private_keys/$name.key.pem
root_cert=root_certs/certs/$name.cert.pem
openssl genrsa -aes256 -out ${root_key} $keysize
info "check if key ${Blu}${keyfilename}${RCol} exists"
if [ -f ${root_key} ];
then
   ok "key does exists"
   chmod 400 ${root_key}
else
   err "key does NOT exists"
fi
## create cert
info "create a root cert";
echo -n "Day to expire: "
read expire_in

openssl req -new -x509 -days $expire_in -key $root_key -sha256 -extensions v3_ca -out $root_cert
info "check if certificate ${Blu}$certfilename${RCol} exists"
if [ -f $root_cert ];
then
   ok "certificate does exists"
   chmod 444 $root_cert
else
   err "certificate does NOT exists"
fi
}
#------------------------------------------------------------------------------------------------------------------------
do_root_remove(){
echo -n "Please specify the name of the cert (without ending): "
read keyfilename
rm -f root_certs/private_keys/${keyfilename}.key.pem
rm -f root_certs/certs/${keyfilename}.cert.pem
}
#------------------------------------------------------------------------------------------------------------------------
do_root_list(){
dir root_certs/certs/
}
#------------------------------------------------------------------------------------------------------------------------
#======================================= INTERMEDIATE ===================================================================
#------------------------------------------------------------------------------------------------------------------------
do_intermediate_create(){
##create key
info "create intermediate key";
echo -n "What root certificate to use: "
read rootname
echo -n "Please specify a name for your intermediate: "
read intername
echo -n "Please specify the keysize: "
read keysize
if ! [[ $keysize =~ $int_regex ]] ; then
  err "Your keysize is not a number --> abort" >&2; exit 1
fi
inter_key=intermediate_certs/private_keys/$intername.key.pem
inter_request=intermediate_certs/certs/$intername.csr.pem
inter_cert=intermediate_certs/certs/$intername.cert.pem
inter_chain=intermediate_certs/certs/$intername-chain.cert.pem

root_key=root_certs/private_keys/$rootname.key.pem
root_cert=root_certs/certs/$rootname.cert.pem

openssl genrsa -aes256 -out $inter_key $keysize
info "check if key ${Blu}$inter_key${RCol} exists"
if [ -f $inter_key ];
then
   ok "key does exists"
   chmod 400 $inter_key
else
   err "key does NOT exists"
fi
# create request
info "create a intermediate cert";
echo -n "Which intermediate key to use: "
read filename

openssl req -config intermediate/openssl.cnf \
    -sha256 -new -key $inter_key \
    -out $inter_request
info "check if request ${Blu}$inter_request${RCol} exists"
if [ -f $inter_request ];
then
   ok "certificate does exists"
else
   err "certificate does NOT exists"
fi
# sign intermediate request with root cert
echo -n "Which root key to use: "
read root_key
openssl ca \
    -keyfile $root_key \
    -cert $root_cert \
    -extensions v3_ca -notext -md sha256 \
    -in $inter_request \
    -out $inter_cert

chmod 444 $inter_cert
## verify certificate
test = `grep "OK" openssl verify -CAfile $root_cert $inter_cert`
if [ "$test" == "OK"  ]; then
  ok "your intermediate certificate was successfuly created"
else
  err "something went wrong, sorry!"
fi

## create chainfile for intermediate
cat $inter_cert $root_cert > $inter_chain
}
#------------------------------------------------------------------------------------------------------------------------
do_intermediate_list(){
dir intermediate_certs/private_keys/
}
#------------------------------------------------------------------------------------------------------------------------
do_intermediate_remove(){
echo -n "Please specify the name of the cert (without ending): "
read name
rm -f intermediate_certs/private_keys/$name.key.pem
rm -f intermediate_certs/certs/$name.csr.pem
rm -f intermediate_certs/certs/$name.cert.pem
rm -f intermediate_certs/certs/$name-chain.cert.pem

}
#------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------------
#======================================= CLIENT =========================================================================
#------------------------------------------------------------------------------------------------------------------------
do_client_create(){
##create key
info "create client key";
echo -n "What intermediate certificate to use: "
read intername
echo -n "Please specify a name for your client certificate (www.example.com): "
read clientname
echo -n "Please specify the keysize (2048): "
read keysize
if ! [[ $keysize =~ $int_regex ]] ; then
  err "Your keysize is not a number"
fi

inter_key = client_certs/private_keys/$intername.key.pem
inter_cert = client_certs/certs/$intername.cert.pem

client_key = client_certs/private_keys/$clientname.key.pem
client_request = client_certs/certs/$clientname.csr.pem
client_cert = client_certs/certs/$clientname.cert.pem

openssl genrsa -out client_key $keysize
chmod 400 client_key
## create request
info "Make sure that the Organization Name you choose below matches the one set for your CA root "
openssl req -sha256 -new -client_key -out client_request
## sign
openssl ca -keyfile inter_key  -cert inter_cert \
    -extensions usr_cert -notext -md sha256 \
    -in client_request -out client_cert
chmod 444 client_cert
## verify
openssl x509 -in client_cert -noout -text
## create chainfile
}

#------------------------------------------------------------------------------------------------------------------------
#======================================= COMMON =========================================================================
#------------------------------------------------------------------------------------------------------------------------
do_root_remove(){
info "remove root cert";
}



do_setup(){
info "create directories";
for d in root_certs intermediate_certs client_certs
do
mkdir $d
cd $d
mkdir certs
mkdir private_keys
chmod 700 private_keys
mkdir public_keys
touch index.txt
echo 1000 > serial
cd ../
done
}

do_remove(){
for d in root_certs intermediate_certs client_certs
do
rm -Rf $d
done
}

do_about(){
echo -e "\n\n${BYel}Y${RCol}our ${BYel}O${RCol}wn ${BYel}C${RCol}ertificate ${BYel}A${RCol}uthority";
echo -e "http://github.com/PatWie/${BYel}yoca${RCol}\n------------------------------------\n";
}

######## MAIN-LOOP
do_about
case "$1" in
root)
  case "$2" in
  create)
  do_root_create
  ;;
  list)
  do_root_list
  ;;
  remove)
  do_root_remove
  ;;
  esac
;;
intermediate)
  case "$2" in
  create)
  do_intermediate_create
  ;;
  list)
  do_intermediate_list
  ;;
  remove)
  do_intermediate_remove
  ;;
  esac
;;
setup)
do_setup
;;
remove)
do_remove
;;
*)
echo "Usage: $(basename $0) {setup|remove}         - or -"
echo "Usage: $(basename $0) {root|intermediate|client} {create|list|remove}"
exit 1
;;
esac
exit
