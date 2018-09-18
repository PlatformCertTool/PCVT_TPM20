#!/bin/bash
# Workflow for validating and comparing the EK certificate to the platform certificate without TPM interaction

BLUE='\033[1;34m'
NC='\033[0m'
GREEN='\033[1;32m'
RED='\033[1;31m'

zz="0"

while [[ $# > 0 ]]
do
key="$1"

case $key in
    -zz)
    zz="1"
    ;;
    -ekcca)
    ekcca="$2"
    shift
    ;;
	-ekc)
    ekc="$2"
    shift
    ;;
	-ekcxmlout)
    ekcxmlout="$2"
    shift
    ;;
	-pcca)
    pcca="$2"
    shift
    ;;
	-pc)
    pc="$2"
    shift
    ;;
	-pcd)
    pcd="$2"
    shift
    ;;
    -crlurl)
    crlurl="$2"
    shift
    ;;
    -pcxmlout)
    pcxmlout="$2"
    shift
    ;;
    -v)
    v="-v"
    ;;

    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

# Test legitimate combinations


valid=1

error_msg_flags="Missing required command-line arguments: "

# ek ca cert required
if [ -z "$ekcca" ]
then
  valid=0
  error_msg_flags="$error_msg_flags -ekcca"
fi

# ek cert required
if [ -z "$ekc" ]
then
  valid=0
  error_msg_flags="$error_msg_flags -ekc"
fi

# platform ca cert required
if [ -z "$pcca" ]
then
  valid=0
  error_msg_flags="$error_msg_flags -pcca"
fi

# crl required
if [ -z "$crlurl" ]
then
  valid=0
  error_msg_flags="$error_msg_flags -crlurl"
fi

# one of -pc or -pcd is required
if ( [ -z "$pc" ] && [ -z "$pcd" ] ) || ( [ -n "$pc" ] && [ -n "$pcd" ] )
then
  valid=0
  error_msg_flags="$error_msg_flags (One of -pc or -pcd is required)"
fi

if [ $valid == 0 ]
then
  echo ""
  >&2 printf "${RED}ERROR: $error_msg_flags\n${NC}"
  echo ""
  echo "$0: Validating and Comparing the EK Certificate to the Platform Certificate"
  echo "Usage: $0 [OPTIONS]"
  echo "OPTIONS:"
  echo "          -ekcca <filename>     (EK CA Bundle file)"
  echo "                                Use this file containing a list of certificate files in the CA chain"
  echo "                                REQUIRED for EK Certificate verification"
  echo "          -ekc <filename>       (EK certificate file)"
  echo "                                REQUIRED for EK Certificate verification"
  echo "          -ekcxmlout <filename> (XML representation of the EK Certificate File)"
  echo "                                If this is present the EK Cert serial # and Issuer will be output to this XML formatted file"
  echo "          -pcca <filename>      Platform CA cert that signs the platform cert"
  echo "                                REQUIRED for Platform Certificate verification"
  echo "          -pc <filename>        (Platform certificate file)"
  echo "          -pcd <directory>      (drectory of Platform certificate files)"
  echo "                                One of -pc or -pcd is required"
  echo "          -crlurl <URL>         (URL to where CRL can be Downloaded)"
  echo "                                REQUIRED for CRL verification of Platform certificate"
  echo "          -pcxmlout <filename>  (XML representation of the Platform Certificate File)"
  echo "                                If this is present the Platform Cert serial # and Issuer will be output to this XML formatted file"
  echo "          -v                    (Verbose  mode)"
  exit
  

else
  
  # Get working directory
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  
  # Show options
  #echo "Options selected:"
  #echo "ekcca: $ekcca"
  #echo "ekc: $ekc"
  #echo "ekcxmlout: $ekcxmlout"
  #echo "pcca: $pcca"
  #echo "pc: $pc"
  #echo "pcd: $pcd"
  #echo "crlurl: $crlurl"
  #echo "pcxmlout: $pcxmlout"
  #echo "v: $v"
  
  # Verify EK cert against input CA certs
  >&2 echo " "
  >&2 printf "${BLUE}Verifying EK cert${NC}\n"
  
  >&2 echo " "
  if [ "$zz" -eq "1" ]
  then
    read -n 1
  fi  
  
  >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyEKCert $ekcca $ekc $v"
  (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyEKCert $ekcca $ekc $v)
  rc=$?
  if [ "$rc" -ne "0" ]
  then
    >&2 printf "${RED}Failed to verify EK cert${NC}\n"
    #exit $rc
  else
    >&2 printf "${GREEN}Successfully verified EK cert${NC}\n"
  fi

  # Output EK certificate XML file by parsing the EK certificate file
  if [ -n "$ekcxmlout" ]
  then   
    >&2 echo " "
    if [ "$zz" -eq "1" ]
    then
      read -n 1
    fi
    >&2 printf "${BLUE}Generating XML file containing the EK information${NC}\n"
    >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.EKCertToPlatformCertXml $ekc $ekcxmlout $v"
    (java -cp .$DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.EKCertToPlatformCertXml $ekc $ekcxmlout $v)
    rc=$?
    if [ "$rc" -ne "0" ]
    then
      >&2 printf "${RED}Failed to generate EK Certificate Information XML file $ekcxmlout ${NC}\n"
      #exit $rc
    else
      >&2 printf "${GREEN}Successfully generate EK Certificate Information XML file $ekcxmlout ${NC}\n"
    fi
  fi
  
  # Verify Platform cert against input CA certs and perform CRL checking
  # Verify that EK cert and Platform cert match
  # Output Platform Certificate XML file by parsing the Platform certificate file (optional)
  if [ -n "$pc" ]
  then
    pcparse=$pc
  else
    pcparse=$pcd
  fi
  >&2 echo " "
  >&2 printf "${BLUE}Verifying Platform cert${NC}\n"
  >&2 echo " "
  if [ "$zz" -eq "1" ]
  then
    read -n 1
  fi  
  >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyPlatformCert $pcca $pcparse $crlurl $ekc $v $pcxmlout"
  (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyPlatformCert $pcca $pcparse $crlurl $ekc $v $pcxmlout)
  rc=$?
  if [ "$rc" -ne "0" ]
  then
    >&2 printf "${RED}Failed to verify Platform cert${NC}\n"
    #exit $rc
  else
    >&2 printf "${GREEN}Successfully verified Platform cert${NC}\n"
  fi
fi
