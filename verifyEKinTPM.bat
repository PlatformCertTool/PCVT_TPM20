@echo off 
:: Workflow for verifying TPM Public Key against Platform Certificate 

SETLOCAL

set BLUE=[94m
set NC=[0m
set GREEN=[92m
set RED=[91m

set zz=0
set name=%0

:START
    if (%1)==() (
        goto END    
    )
    if %1==-zz (
        set zz=1
    )
    if %1==-ekcca if not (%2)==() (
        set ekcca=%2
        shift
    )
    if %1==-crl if not (%2)==() (
        set crl=%2
        shift
    )
    if %1==-ekc if not (%2)==() (
        set ekc=%2
        shift
    )
    if %1==-ekcout if not (%2)==() (
        set ekcout=%2
        shift
    )   
    if %1==-ekcxmlout if not (%2)==() (
        set ekcxmlout=%2
        shift
    )
    if %1==-ekindex if not (%2)==() (
        set ekindex=%2
        shift
    )       
    if %1==-ekmethod if not (%2)==() (
        set ekmethod=%2
        shift
    )       
    if %1==-ownerpw if not (%2)==() (
        set ownerpw=%2
        shift
    )
    if %1==-endpw if not (%2)==() (
        set endpw=%2
        shift
    )
    if %1==-v (
        set v=-v
    )
    shift
    goto START
:END
    
:: Test legitimate combinations

set valid=1

:: ek ca required
if not defined ekcca (
    set valid=0
)

:: if ekcxmlout is included, then either ekc or ekcout must also be included
if not defined ekcout if not defined ekc (
    set ekctmp=__temp_ekc.pem
)

if %valid%==0 (
    echo %name%: Perform validation of Platform Certificate against TPM Certificate
    echo Usage: %name% [OPTIONS]
    echo OPTIONS:
    echo           -ekcca                ^(EK CA Bundle file^) 
    echo                                 Use this file containing a list of certificate files in the CA chain
    echo                                 REQUIRED for EK Certificate verification
    echo           -ekc ^<filename^>       ^(Endorsement Certificate File^)
    echo                                 Use this Endorsement Key Certificate
    echo           -ekcout ^<filename^>    ^(Output Endorsement Certificate File^)
    echo                                 If this is present the Endorsement Key Certificate will be output to this PEM formatted file
    echo           -ekcxmlout ^<filename^> ^(XML representation of the Output Endorsement Certificate File^)
    echo                                 If this is present the EK Cert serial # and Issuer will be output to this XML formatted file
    echo           -ekindex ^<1 ^| 2^>      ^(Pre-defined index value indicating which EK Cert in NV to use^)
    echo                                 1=RSA, 2=ECC. If not present RSA will be attempted first and if not valid ECC will be used
    echo           -ekmethod ^<1 ^| 2^>     ^(Pre-defined method to be used to validate the TPM^)
    echo                                 1=Make/Activate Credential, 2=Salted Session. If not present Salted Session will be used
    echo           -ownerpw ^<password^>   ^(TPM owner password^)
    echo           -endpw ^<password^>     ^(TPM endorsement password^)
    echo           -v                    ^(Verbose  mode^)
    exit /b
)

:: Get working directory
set DIR=%cd%

:: Verify EK from TPM

:: build optional command line vals string

set op_cmd_args=

if defined ekc ( 
    set op_cmd_args=%op_cmd_args% -ekc %ekc%
)

if defined ekcout ( 
    set op_cmd_args=%op_cmd_args% -ekout %ekcout%
) else (
    if defined ekctmp (
        set op_cmd_args=%op_cmd_args% -ekout %ekctmp%
    )
)

if defined ekindex ( 
    set op_cmd_args=%op_cmd_args% -ekindex %ekindex%
)

if defined ekmethod ( 
    set op_cmd_args=%op_cmd_args% -ekmethod %ekmethod%
)

if defined ownerpw ( 
    set op_cmd_args=%op_cmd_args% -ownerpw %ownerpw%
)

if defined endpw ( 
    set op_cmd_args=%op_cmd_args% -endorsementpw %endpw%
)

echo. 1>&2
echo %BLUE%validating the TPM%NC% 1>&2
echo. 1>&2

if %zz%==1 pause

echo "%DIR%\getAndVerifyEK" -ekcacert %ekcca% %op_cmd_args% %v% 1>&2
("%DIR%\getAndVerifyEK" -ekcacert %ekcca% %op_cmd_args% %v%)

if %errorlevel% neq 0 (
    echo %RED%Failed to validate TPM%NC% 1>&2
    set do_crl_check=0
) else (
    echo %GREEN%Successfully validated TPM%NC% 1>&2
    set do_crl_check=1
)

:: determine which ekc file to use, either one from the tpm,  command-line
if defined ekc (
    set the_ekc=%ekc%   
) else (
    if defined ekcout (
        set the_ekc=%ekcout%
    ) else (
        set the_ekc=%ekctmp%
    )
)

:: Verify the EK certificate using the Java verifcation which also checks the CRL
if %do_crl_check%==1 (
    echo. 1>&2
    echo %BLUE%Verifying that the EK certificate has not been revoked%NC% 1>&2
    echo. 1>&2
    
    if %zz%==1 pause 
    
    echo java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.VerifyEKCert %ekcca% %the_ekc% %v% 1>&2 
    (java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.VerifyEKCert %ekcca% %the_ekc% %v%)
)
:: font color is not displayed if not separating code
if %do_crl_check%==1 (
    if %errorlevel% neq 0 (
        echo %RED%Failed to verify EK against CRL - The EK certificate may have been revoked%NC% 1>&2
    ) else (
        echo %GREEN%Successfully verified that the EK certificate has NOT been revoked%NC% 1>&2
    )
)

:: Output EK certificate XML file by parsing the EK certificate file
if defined ekcxmlout (
    echo. 1>&2
    echo %BLUE%Generating XML file containing the EK information%NC% 1>&2
    echo. 1>&2
    
    if %zz%==1 pause 
    
    echo java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.EKCertToPlatformCertXml %the_ekc% %ekcxmlout% %v% 1>&2
    (java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.EKCertToPlatformCertXml %the_ekc% %ekcxmlout% %v%)
)
:: font color is not displayed if not separating code
if defined ekcxmlout (
    if %errorlevel% neq 0 (
        echo %RED%Failed to generate EK Certificate Information XML file %ekcxmlout%%NC% 1>&2
    ) else (
        echo %GREEN%Successfully generate EK Certificate Information XML file %ekcxmlout%%NC% 1>&2
    )
)

:: remove ekc file if the user did not request this as output on the command line
if defined ekctmp del %ekctmp%

ENDLOCAL
