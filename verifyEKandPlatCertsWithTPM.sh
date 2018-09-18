#!/bin/bash
# Workflow for validating and comparing the EK certificate to the platform certificate with TPM interaction

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
    -ekcout)
    ekcout="$2"
    shift
    ;;
    -ekindex)
    ekindex="$2"
    shift
    ;;
    -ekcxmlout)
    ekcxmlout="$2"
    shift
    ;;
    -endpw)
    endpw="$2"
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
    pc="$2"
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

# one of ekc or ekcout is required
if [ -n "$ekcout" ]
then
  ekcparse=$ekcout
else
  ekcparse=$ekc
fi

if [ -z "$ekcparse" ]
then
  valid=0
  error_msg_flags="$error_msg_flags (One of -ekc or -ekout is required)"
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
  echo "          -ekcout <filename>    (Output Endorsement Certificate File)"
  echo "                                If this is present the Endorsement Key Certificate will be output to this PEM formatted file"
  echo "                                One of -ekc or -ekcout is required"   
  echo "          -ekindex <1 | 2>      (Pre-defined index value indicating which EK Cert in NV to use)"
  echo "                                1=RSA, 2=ECC. If not present RSA will be attempted first and if not valid ECC will be used"
  echo "          -ekcxmlout <filename>  (XML representation of the EK Certificate File)"
  echo "                                If this is present the EK Cert serial # and Issuer will be output to this XML formatted file"
  echo "          -endpw <password>     (TPM endorsement password)"
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
  # echo "Options selected:"
  # echo "ekcca: $ekcca"
  # echo "ekc: $ekc"
  # echo "ekout: $ekout"
  # echo "ekcxmlout: $ekcxmlout"
  # echo "endpw: $endpw"
  # echo "pcca: $pcca"
  # echo "pc: $pc"
  # echo "pcd: $pcd"
  # echo "crlurl: $crlurl"
  # echo "pcxmlout: $pcxmlout"
  # echo "v: $v"
  
  # Verify EK cert from TPM

  # build optional command line vals string
  op_cmd_args=""
  if [ -n "$ekc" ] 
  then
    op_cmd_args="$op_cmd_args -ekc $ekc"
  fi
  
  if [ -n "$ekcout" ] 
  then
    op_cmd_args="$op_cmd_args -ekout $ekcout"
  fi

  if [ -n "$ekindex" ] 
  then
    op_cmd_args="$op_cmd_args -ekindex $ekindex"
  fi

  if [ -n "$endpw" ] 
  then
    op_cmd_args="$op_cmd_args -endorsementpw $endpw"
  fi

  >&2 echo " "
  >&2 printf "${BLUE}Validating the EK cert in TPM${NC}\n"
  >&2 echo " "
  if [ "$zz" -eq "1" ]
  then
    read -n 1
  fi  
  >&2 echo "$DIR/getAndVerifyEK2 -ekcacert $ekcca $op_cmd_args $v"
  ($DIR/getAndVerifyEK2 -ekcacert $ekcca $op_cmd_args $v)
  rc=$?
  if [  "$rc" -ne "0" ]
  then
    >&2 printf "${RED}Failed to validate EK cert in TPM${NC}\n"
    do_crl_check=0
  else
    >&2 printf "${GREEN}Successfully validated EK cert in TPM${NC}\n"
    do_crl_check=1
  fi

# Verify the EK certificate using the Java verifcation which also checks the CRL
  if [ "$do_crl_check" -eq "1" ]
  then
    >&2 echo " "
    >&2 printf "${BLUE}Verifying that the EK certificate has not been revoked${NC}\n"
    >&2 echo " "
    if [ "$zz" -eq "1" ]
    then
      read -n 1
    fi
    >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyEKCert $ekcca $ekcparse $v"
    (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyEKCert $ekcca $ekcparse $v)
    rc=$?
    if [ "$rc" -ne "0" ]
    then
      >&2 printf "${RED}Failed to verify EK against CRL - The EK certificate may have been revoked${NC}\n"
    else
      >&2 printf "${GREEN}Successfully verified that the EK certificate has NOT been revoked${NC}\n"
    fi
  fi

  # Output EK certificate XML file by parsing the EK certificate file
  if [ -n "$ekcxmlout" ]
  then   
    >&2 echo " "
    >&2 printf "${BLUE}Generating XML file containing the EK information${NC}\n"
    >&2 echo " "
    if [ "$zz" -eq "1" ]
    then
      read -n 1
    fi  
    >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.EKCertToPlatformCertXml $ekcparse $ekcxmlout $v"
    (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.EKCertToPlatformCertXml $ekcparse $ekcxmlout $v)
    rc=$?
    if [  "$rc" -ne "0" ]
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
  >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyPlatformCert $pcca $pcparse $crlurl $ekcparse $v $pcxmlout"
  (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyPlatformCert $pcca $pcparse $crlurl $ekcparse $v $pcxmlout)
  rc=$?
  if [  "$rc" -ne "0" ]
  then
    >&2 printf "${RED}Failed to verify Platform cert${NC}\n"
    #exit $rc
  else
    >&2 printf "${GREEN}Successfully verified Platform cert${NC}\n"
  fi
fi
