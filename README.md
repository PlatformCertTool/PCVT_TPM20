
TPM 2.0 PLATFORM CERTIFICATE VERIFICATION TOOLS INTSALLATION GUIDE
==================================================================

These are the Installation instructions for the TPM 2.0 version of the Platform Certificate Tools package. 

1. DEPENDENCIES
This version of the TPM 2.0 Platform Certificate Verification toolset has the following dependencies.
	
	1. IBM's TPM 2.0 TSS (https://sourceforge.net/projects/ibmtpm20tss/) (version 1045+)
	2. OpenSSL 1.0.x
	3. [optional] IBM's Software TPM 2.0 (https://sourceforge.net/projects/ibmswtpm2/) (version 974+) 
	4. Java JVM 1.7 or greater
	5. Ability to run Linux Bash script

	
2. BUILDING ‘C’ EXECUTABLES
There are two ‘C’ executables used in this package.  These two executables will have to be built and linked into the same directory the tools shell scripts are run in.

	1. To build the two required executable files, getAndVerifyEK, and getAndVerifyEK2, follow the instructions in their respective readme.txt files. The readme file are found in the following two directories (relative to the toolset installation directory), ./src/c/getAndVerifyEK, and ./src/c/getAndVerifyEK2.

	2. Once those executable files are built link them into the installation directory for this toolset.

		# cd <toolset installation dir>.
		# ln -s ./src/c/getAndVerifyEK/getAndVerifyEK .
		# ln -s ./src/c/getAndVerifyEK2/getAndVerifyEK2 .
	
	3. Link IBM TSS libraries to current directory.
		
		# ln -s <path to ibmtss>/ibmtss1045/utils/libtss.so* .
	
3. Shell Scripts
The shell scripts have to be designated as executable files.

	1. Excute the following command from the command line
		
		# chmod +x *.sh# PCVT_TPM20
Platform Certificate Validation Tool - TPM 2.0

4. TPM 2.0 PLATFORM CERTIFICATE VERIFICATION TOOLS
The TPM2_Verification_Too_Usage file describes typical use cases for this TPM 2.0 version of the Platform Certificate Tools package. 

The first three use cases indicate how the tools may be used together in a manufacturing setting to obtain the EK Certificate from the platform, create the Platform Certificate, and then verify the binding between the two certificates. It will also generate XML files containing the information in the platform certificate to more easily access information about the certificates.

The fourth use case shows how the tools may be used out in the field to verify that the Endorsement Key (EK) Certificate and the Platform Certificate match.

This file has the command line usage and the expected output examples files.

5. C code Readme Files

The Readme_getAndVerifyEK.txt and Readme_getAndVerifyEK2.txt files describe how to generate and compile the C tools
getAndVerifyEK and getAndVerifyEK2

a. Overview

This tool is designed to be used by a customer after a platform's delivery, to verify the signature of the Endorsement Key (EK) Certificate and that it matches the EK in the TPM. It performs the following steps.

o	Fetch EK Cert from TPM NV – find the correct certificate based Template 
o	Verify the EK Cert against the input EK CA Public Key Chain 
o	Compare the EK in the Cert with the EK in the TPM 


b. Dependencies

    1. IBM's TPM 2.0 TSS (https://sourceforge.net/projects/ibmtpm20tss/) (verison 1045+)

    2. OpenSSL 1.0.x


c. Build Instructions

    1. Build OpenSSL (see instructions inside OpenSSL package)

    2. Build IBM's TPM 2.0 TSS (see instructions inside IBM TSS pacgage)

    3. Link "ibmtss1045/utils/tss2/" and "ibmtss1045/utils/libtss.so*" to current directory

    4. Run commands below:
	    # cd src
	    # make
	    # cd ..


d. Run

    To run this exectable file, run "./getAndVerifyEK2".
    
    END of README
