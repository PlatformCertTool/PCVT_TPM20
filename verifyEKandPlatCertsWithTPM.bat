@echo off 
:: Workflow for validating and comparing the EK certificate to the platform certificate with TPM interaction

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
    if %1==-ekc if not (%2)==() (
        set ekc=%2
        shift
    )
    if %1==-ekcout if not (%2)==() (
        set ekcout=%2
        shift
    )
    if %1==-ekindex if not (%2)==() (
        set ekindex=%2
        shift
    )
    if %1==-ekcxmlout if not (%2)==() (
        set ekcxmlout=%2
        shift
    )
    if %1==-endpw if not (%2)==() (
        set endpw=%2
        shift
    )
    if %1==-pcca if not (%2)==() (
        set pcca=%2
        shift
    )
    if %1==-pc if not (%2)==() (
        set pc=%2
        shift
    )
    if %1==-pcd if not (%2)==() (
        set pcd=%2
        shift
    )
    if %1==-crlurl if not (%2)==() (
        set crlurl=%2
        shift
    )
    if %1==-pcxmlout if not (%2)==() (
        set pcxmlout=%2
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

set error_msg_flags=Missing required command-line arguments:

:: ek ca cert required
if not defined ekcca (
    set valid=0
    set error_msg_flags=%error_msg_flags% -ekcca
)

:: platform ca cert required
if not defined pcca (
    set valid=0
    set error_msg_flags=%error_msg_flags% -pcca
)

:: crl required
if not defined crlurl (
    set valid=0
    set error_msg_flags=%error_msg_flags% -crlurl
)

:: one of -pc or -pcd is required
if not defined pc if not defined pcd (
    set valid=0
    set error_msg_flags=%error_msg_flags% [One of -pc or -pcd is required]
)
if defined pc if defined pcd (
    set valid=0
    set error_msg_flags=%error_msg_flags% [One of -pc or -pcd is required]
)

:: one of ekc or ekcout is required
if defined ekcout (
    set ekcparse=%ekcout%
) else (
    set ekcparse=%ekc%
)

if not defined ekcparse (
    set valid=0
    set error_msg_flags=%error_msg_flags% [One of -ekc or -ekout is required]
)

if %valid%==0 (
    echo. 1>&2
    echo %RED%ERROR: %error_msg_flags%%NC% 1>&2
    echo. 1>&2
    
    echo %name%: Perform validation of Platform Certificate against TPM Certificate
    echo Usage: %name% [OPTIONS]
    echo OPTIONS:
    echo           -ekcca ^<filename^>     ^(EK CA Bundle file^)
    echo                                 Use this file containing a list of certificate files in the CA chain
    echo                                 REQUIRED for EK Certificate verification
    echo           -ekc ^<filename^>       ^(EK certificate file^)
    echo                                 REQUIRED for EK Certificate verification

    echo           -ekcout ^<filename^>    ^(Output Endorsement Certificate File^)
    echo                                 If this is present the Endorsement Key Certificate will be output to this PEM formatted file
    echo                                 One of -ekc or -ekcout is required   
    echo           -ekindex ^<1 ^| 2^>      ^(Pre-defined index value indicating which EK Cert in NV to use^)
    echo                                 1=RSA, 2=ECC. If not present RSA will be attempted first and if not valid ECC will be used    
    echo           -ekcxmlout ^<filename^> ^(XML representation of the EK Certificate File^)
    echo                                 If this is present the EK Cert serial # and Issuer will be output to this XML formatted file
    echo           -endpw ^<password^>     ^(TPM endorsement password^)
    echo           -pcca ^<filename^>      Platform CA cert that signs the platform cert
    echo                                 REQUIRED for Platform Certificate verification
    echo           -pc ^<filename^>        ^(Platform certificate file^)
    echo           -pcd ^<directory^>      ^(drectory of Platform certificate files^)
    echo                                 One of -pc or -pcd is required
    echo           -crlurl ^<URL^>         ^(URL to where CRL can be Downloaded^)
    echo                                 REQUIRED for CRL verification of Platform certificate
    echo           -pcxmlout ^<filename^>  ^(XML representation of the Platform Certificate File^)
    echo                                 If this is present the Platform Cert serial # and Issuer will be output to this XML formatted file
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
)

if defined ekindex ( 
    set op_cmd_args=%op_cmd_args% -ekindex %ekindex%
)

if defined endpw ( 
    set op_cmd_args=%op_cmd_args% -endorsementpw %endpw%
)

echo. 1>&2
echo %BLUE%validating the EK cert in TPM%NC% 1>&2
echo. 1>&2

if %zz%==1 pause

echo "%DIR%\getAndVerifyEK2" -ekcacert %ekcca% %op_cmd_args% %v% 1>&2
("%DIR%\getAndVerifyEK2" -ekcacert %ekcca% %op_cmd_args% %v%)

if %errorlevel% neq 0 (
    echo %RED%Failed to validate EK cert in TPM%NC% 1>&2
    set do_crl_check=0
) else (
    echo %GREEN%Successfully validated EK cert in TPM%NC% 1>&2
    set do_crl_check=1
)

:: Verify the EK certificate using the Java verifcation which also checks the CRL
if %do_crl_check%==1 (
    echo. 1>&2
    echo %BLUE%Verifying that the EK certificate has not been revoked%NC% 1>&2
    echo. 1>&2
    
    if %zz%==1 pause 
    
    echo java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.VerifyEKCert %ekcca% %ekcparse% %v% 1>&2 
    (java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.VerifyEKCert %ekcca% %ekcparse% %v%)
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
    
    echo java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.EKCertToPlatformCertXml %ekcparse% %ekcxmlout% %v% 1>&2
    (java -cp "%DIR%\tpm20VerificationToolset1.1.jar;lib\*" com.trustiphi.tpm2verification.EKCertToPlatformCertXml %ekcparse% %ekcxmlout% %v%)
)
:: font color is not displayed if not separating code
if defined ekcxmlout (
    if %errorlevel% neq 0 (
        echo %RED%Failed to generate EK Certificate Information XML file %ekcxmlout%%NC% 1>&2
    ) else (
        echo %GREEN%Successfully generate EK Certificate Information XML file %ekcxmlout%%NC% 1>&2
    )
)

:: Verify Platform cert against input CA certs and perform CRL checking
:: Verify that EK cert and Platform cert match
:: Output Platform Certificate XML file by parsing the Platform certificate file (optional)

if defined pc (
    set pcparse=%pc%
) else (
    set pcparse=%pcd%
)

echo. 1>&2
echo %BLUE%Verifying Platform cert%NC% 1>&2
echo. 1>&2

if %zz%==1 pause

echo java -cp "%DIR%\tpm20VerificationToolset1.1.jar;%DIR%\lib\*" com.trustiphi.tpm2verification.VerifyPlatformCert %pcca% %pcparse% %crlurl% %ekcparse% %v% %pcxmlout%
(java -cp "%DIR%\tpm20VerificationToolset1.1.jar;%DIR%\lib\*" com.trustiphi.tpm2verification.VerifyPlatformCert %pcca% %pcparse% %crlurl% %ekcparse% %v% %pcxmlout%)

if %errorlevel% neq 0 (
    echo %RED%Failed to verify Platform cert%NC% 1>&2
) else (
    echo %GREEN%Successfully verified Platform cert%NC% 1>&2
)

ENDLOCAL
