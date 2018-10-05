GetAndVerifyEK

1. Overview

This tool is designed to be used to verify an Endorsement Key (EK) and TPM during a platform's manufacturing process for platform certificate generation. It performs the following steps.

o	If no input EK Cert: Get the EK Cert from TPM NV
o	If input EK Cert: Load EK Cert (PEM)
o	Verify the EK Cert against the input CA Certificate Chain
o	Verify EK (Sorted session, or Make/Activate Credential)
o	If input EK Cert: Compare the EK in the Cert with the EK in the TPM (OpenSSL)


2. Dependencies

This software has the following dependencies.

    1. IBM's TPM 2.0 TSS (https://sourceforge.net/projects/ibmtpm20tss/) (verison 1045+)

    2. OpenSSL 1.0.x

    3. [optional] IBM's Software TPM 2.0 (https://sourceforge.net/projects/ibmswtpm2/) (version 974+) (This tool employs two techniques for verifying that private part of the EK is in the TPM.  This package is only needed for the make/activate-credential EK verifcation technique. This library is required to emplow the EK by make/activate credential verification because the make-credential step is done in a SW TPM. For more details on the verfication techniques, see the design document.)


3. Build Instructions

    1. Build OpenSSL (see instructions inside OpenSSL package)

    2. Build IBM's TPM 2.0 TSS (see instructions inside IBM TSS pacgage)

    3. Link "ibmtss1045/utils/tss2/" and "ibmtss1045/utils/libtss.so*" to current directory

    4. Run commands below:
	    # cd src
	    # make
	    # cd ..
	
    5. [optional] Build IBM's Software TPM 2.0 (see instructions inside IBM TPM package)	

	
4. Run Instructions

    1. [optional] Run IBM's SW TPM:
	    # cd <your_path_to_ibmtpm>/ibmtpm974/src/
	    # ./tmp_server &
	    # cd <your_path_to_ibmtss>/ibmtss1045/utils/
	    # ./powerup
	    # ./startup

    2. To run this exectable file, run "./getAndVerifyEK".

 5. Usage

  getAndVerifyEK  -ekcacert <filename> [-ekc <filename>] [-ekout <filename>] [-ekindex <1 | 2>] [-ekmehod <1 | 2>] [-endorsementpw <password>] [-ownerpw <password>] [-v]

  -ekcacert <filename>  where the file contains a list of filenames of CA certificates
                        (including the root and intermeidate ones) for the EK certificate
  -ekc <filename>       where the file contains the EK certificate
  -ekout <filename>     where filename is the name of the output EK Cert PEM file
  -ekindex <1 | 2>      The built-in EK certificate "index" indicating which EK certificate
                        in the NV to use, RSA, or ECC. 1 for RSA and 2 for ECC.
                        This is not a required option. If not included on the command line,
                        the code will attempt to use RSA and if not found will use ECC.
  -ekmethod <1 | 2>     Indicates which method will be used for TPM validation.
                        In method 1, a make credential and activate credential are performed,
                        while in method 2, a salted session is used. This is not a required option.
                        If not included on the command line, method 2 will be used.
  -endorsementpw        password for endorsement auth
  -ownerpw              password for owner auth
  -v                    verbose mode
