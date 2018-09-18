#!/bin/bash
# Workflow for verifying TPM Public Key against Platform Certificate

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
    -crl)
    crl="$2"
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
    -ekcxmlout)
    ekcxmlout="$2"
    shift
    ;;
    -ekindex)
    ekindex="$2"
    shift
    ;;
    -ekmethod)
    ekmethod="$2"
    shift
    ;;
    -ownerpw)
    ownerpw="$2"
    shift
    ;;
    -endpw)
    endpw="$2"
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


# ek ca required
if [ -z "$ekcca" ]
then
  valid=0
fi

# if ekcxmlout is included, then either ekc or ekcout must also be included 
if [ -z "$ekcout" ] && [ -z "$ekc" ]
then
    ekctmp="__temp_ekc.pem"
fi

#if [ -n "$ekcxmlout" ]
#then
#  if [ -z "$ekcparse" ]
#  then
#    valid=0
#    echo ""
#    >&2 printf "${RED}ERROR: If -ekcxmlout is used, at least one of -ekcout or -ekc must also be used.\n${NC}"
#    >&2 printf "${RED}ERROR: (The XML file must be generated from a certificate file)\n${NC}"
#    echo ""
#  fi
#fi

if [ $valid == 0 ]
then
  echo "$0: Perform validation of Platform Certificate against TPM Certificate"
  echo "Usage: $0 [OPTIONS]"
  echo "OPTIONS:"
  echo "          -ekcca                (EK CA Bundle file) "
  echo "                                Use this file containing a list of certificate files in the CA chain"
  echo "                                REQUIRED for EK Certificate verification"
  echo "          -ekc <filename>       (Endorsement Certificate File)"
  echo "                                Use this Endorsement Key Certificate"
  echo "          -ekcout <filename>    (Output Endorsement Certificate File)"
  echo "                                If this is present the Endorsement Key Certificate will be output to this PEM formatted file"
  echo "          -ekcxmlout <filename> (XML representation of the Output Endorsement Certificate File)"
  echo "                                If this is present the EK Cert serial # and Issuer will be output to this XML formatted file"
  echo "          -ekindex <1 | 2>      (Pre-defined index value indicating which EK Cert in NV to use)"
  echo "                                1=RSA, 2=ECC. If not present RSA will be attempted first and if not valid ECC will be used"
  echo "          -ekmethod <1 | 2>     (Pre-defined method to be used to validate the TPM)"
  echo "                                1=Make/Activate Credential, 2=Salted Session. If not present Salted Session will be used"
  echo "          -ownerpw <password>   (TPM owner password)"
  echo "          -endpw <password>     (TPM endorsement password)"
  echo "          -v                    (Verbose  mode)"
  exit
  

else
  
  # Get working directory
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  
  # Show options
  #echo "Options selected:"
  #echo "ekcca: $ekcca"
  #echo "ekc: $ekc"
  #echo "ekcout: $ekcout"
  #echo "ekcxmlout: $ekcxmlout"
  #echo "ekindex: $ekindex"
  #echo "ekmethod: $ekmethod"
  #echo "ownerpw: $ownerpw"
  #echo "endpw: $endpw"
  #echo "ekctmp: $ekctmp"
  #echo "v: $v"
  
  # Verify EK from TPM

  # build optional command line vals string
  op_cmd_args=""
  if [ -n "$ekc" ] 
  then
    op_cmd_args="$op_cmd_args -ekc $ekc"
  fi

  if [ -n "$ekcout" ] 
  then
    op_cmd_args="$op_cmd_args -ekout $ekcout"
  else
    if [ -n "$ekctmp" ] 
    then
      op_cmd_args="$op_cmd_args -ekout $ekctmp"
    fi
  fi

  if [ -n "$ekindex" ] 
  then
    op_cmd_args="$op_cmd_args -ekindex $ekindex"
  fi

  if [ -n "$ekmethod" ] 
  then
    op_cmd_args="$op_cmd_args -ekmethod $ekmethod"
  fi

  if [ -n "$ownerpw" ] 
  then
    op_cmd_args="$op_cmd_args -ownerpw $ownerpw"
  fi

  if [ -n "$endpw" ] 
  then
    op_cmd_args="$op_cmd_args -endorsementpw $endpw"
  fi

  >&2 echo " "
  >&2 printf "${BLUE}Validating the TPM${NC}\n"
  >&2 echo " "
  if [ "$zz" -eq "1" ]
  then
    read -n 1
  fi
  >&2 echo "$DIR/getAndVerifyEK -ekcacert $ekcca $op_cmd_args $v"
  ($DIR/getAndVerifyEK -ekcacert $ekcca $op_cmd_args $v)
  rc=$?
  if [  "$rc" -ne "0" ]
  then
    >&2 printf "${RED}Failed to validate TPM${NC}\n"
    do_crl_check=0
  else
    >&2 printf "${GREEN}Successfully validated TPM${NC}\n"
    do_crl_check=1
  fi

  # determine which ekc file to use, either one from the tpm,  command-line
  if [ -n "$ekc" ]
  then
    the_ekc=$ekc
  else
    if [ -n "$ekcout" ]
    then
      the_ekc=$ekcout
    else
      the_ekc=$ekctmp
    fi
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
    >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyEKCert $ekcca $the_ekc $v"
    (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.VerifyEKCert $ekcca $the_ekc $v)
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

    >&2 echo "java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.EKCertToPlatformCertXml $the_ekc $ekcxmlout $v"
    (java -cp $DIR/tpm20VerificationToolset1.1.jar:$DIR/lib/* com.trustiphi.tpm2verification.EKCertToPlatformCertXml $the_ekc $ekcxmlout $v)
    rc=$?
    if [  "$rc" -ne "0" ]
    then
      >&2 printf "${RED}Failed to generate EK Certificate Information XML file $ekcxmlout ${NC}\n"
      exit $rc
    else
      >&2 printf "${GREEN}Successfully generate EK Certificate Information XML file $ekcxmlout ${NC}\n"
    fi
  fi

# remove ekc file if the user did not request this as output on the command line
  if [ -n "$ekctmp" ]
  then
    (rm $ekctmp)
  fi
  
fi

exit

