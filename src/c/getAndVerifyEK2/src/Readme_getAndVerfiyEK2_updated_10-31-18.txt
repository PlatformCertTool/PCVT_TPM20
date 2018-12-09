GetAndVerifyEK2

1. Overview

This tool is designed to be used by a customer after a platform's delivery, to verify the signature of the Endorsement Key (EK) Certificate and that it matches the EK in the TPM. It performs the following steps.

o	Fetch EK Cert from TPM NV – find the correct certificate based Template 
o	Verify the EK Cert against the input EK CA Public Key Chain 
o	Compare the EK in the Cert with the EK in the TPM 


2. Dependencies

    1. IBM's TPM 2.0 TSS Verison 1045 (https://sourceforge.net/projects/ibmtpm20tss/)
	(Note that if a later version of the TSS is used, modifications to the paths in the "#include" statements in the c source code may be required. Additionally, this code has not been tested with later versions of the TSS).

    2. OpenSSL 1.0.x


3. Build Instructions

    1. Build OpenSSL (see instructions inside OpenSSL package)

    2. Build IBM's TPM 2.0 TSS (see instructions inside IBM TSS package)

    3. Change directory ("cd") to the folder  "<install-dir>/src/c/getAndVerifyEK2". (This is should be the folder containing this readme file.)

    4. Create soft links to the folder "<ibmtss1045-install-dir>/utils/tss2/", and the library files "<ibmtss1045-install-dir>/utils/libtss.so", "<ibmtss1045-install-dir>/utils/libtss.so.0", and "<ibmtss1045-install-dir>/utils/libtss.so.0.1" in the current folder as follows.
	    # ln -s <ibmtss1045-install-dir>/utils/tss2/ .
	    # ln -s <ibmtss1045-install-dir>/utils/libtss.so .
	    # ln -s <ibmtss1045-install-dir>/utils/libtss.so.0 .
	    # ln -s <ibmtss1045-install-dir>/utils/libtss.so.0.1 .

    5. Run commands below:
	    # cd src
	    # make
	    # cd ..


4. Run

    To run this exectable file, run "./getAndVerifyEK2".

5. Usage

    getAndVerifyEK2  -ekcacert <filename> [-ekc <filename>] [-ekout <filename>] [-ekindex <1 | 2>] [-endorsementpw <password>] [-v]

    -ekcacert <filename>  where the file contains a list of filenames of CA certificates
                          (including the root and intermeidate ones) for the EK certificate
    -ekc <filename>       where the file contains the EK certificate
    -ekout <filename>     where filename is the name of the output EK Cert PEM file
    -ekindex <1 | 2>      The built-in EK certificate "index" indicating which EK certificate
                          in the NV to use, RSA, or ECC. 1 for RSA and 2 for ECC.
                          This is not a required option. If not included on the command line,
                          the code will attempt to use RSA and if not found will use ECC.
    -endorsementpw        password for endorsement auth
    -v                    verbose mode