/********
* The terms of the software license agreement included with any software you
* download will control your use of the software.
*
* INTEL SOFTWARE LICENSE AGREEMENT
*
* IMPORTANT - READ BEFORE COPYING, INSTALLING OR USING.
*
* Do not use or load this software and any associated materials (collectively,
* the "Software") until you have carefully read the following terms and
* conditions. By loading or using the Software, you agree to the terms of this
* Agreement. If you do not wish to so agree, do not install or use the Software.
*
* SEE "Intel Software License Agreement" file included with this package.
*
* Copyright Intel, Inc 2017
*
* Initial Development by TrustPhi, LLC, www.trusiphi.com
*/

/* getAndVerifyEK.c: validate EK cert and EK */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/tsscryptoh.h>
#include <tss2/tsscrypto.h>
#include <tss2/Unmarshal_fp.h>

#include <openssl/rand.h>
#include <openssl/pem.h>

#include "config.h"
#include "ekutils.h"
#include "cryptoutils.h"
#include "commonerror.h"
#include "commonutils.h"
#include "commontss.h"
#include "objecttemplates.h"

static uint32_t loadExternal(TSS_CONTEXT *tssContext,
    TPM_HANDLE *objectHandle,
    TPM2B_NAME *name,
    TPMT_PUBLIC *inPublic);

static uint32_t makecredential(TSS_CONTEXT *tssContext,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret,
    TPM_HANDLE handle,
    TPM2B_DIGEST *credential,
    TPM2B_NAME *objectName);

static TPM_RC policyGetDigest(TSS_CONTEXT *tssContext,
    TPMI_SH_AUTH_SESSION sessionHandle);

static TPM_RC createKey(TSS_CONTEXT *tssContext,
    TPM2B_PRIVATE *outPrivate,
    TPM2B_PUBLIC *outPublic,
    TPMI_SH_AUTH_SESSION policySessionHandle,
    TPM_HANDLE parentHandle,
    const char *keyPassword,
    int pwSession);

static TPM_RC startSession(TSS_CONTEXT *tssContext,
    TPMI_SH_AUTH_SESSION *sessionHandle,
    TPM_SE sessionType,
    TPMI_DH_OBJECT tpmKey,
    TPMI_DH_ENTITY bind,
    const char *bindPassword);

static TPM_RC ekCertToX509(unsigned char *ekCertificate,
    uint16_t ekCertLength,
    X509 **ekX509Certificate);

static TPM_RC validateEkCertRoot(X509 **ekX509Certificate,
    const char *listFilename);

static TPM_RC validateEkCert(TSS_CONTEXT *tssContext,
    TPMI_RH_NV_INDEX *ekCertIndex,
    const char *ekcacert,
    const char *ekc,
    const char *endorsementPw,
    const char *ekout,
    TPM_HANDLE *ekKeyHandle,
    TPMT_PUBLIC *ekPub);

static TPM_RC readEkCert(const char* filename, X509 **ekX509Certificate);

static TPM_RC getCertType(X509 **ekX509Certificate, 
    TPMI_RH_NV_INDEX *ekCertIndex);

static TPM_RC compareEkPub(TPMT_PUBLIC *ekPub, X509 **ekX509Certificate);

static TPM_RC validateEk1(TSS_CONTEXT *tssContext, 
    TPMI_RH_NV_INDEX ekCertIndex, 
    const char *ownerPw, const char *endorsementPw, 
    TPM_HANDLE *ekKeyHandle, TPMT_PUBLIC *ekPub);

static TPM_RC validateEk2(TSS_CONTEXT *tssContext, 
    TPMI_RH_NV_INDEX ekCertIndex,
    const char* endorsementPw,
    TPM_HANDLE *ekKeyHandle);

static TPM_RC createEkPrimary(TSS_CONTEXT *tssContext,
    TPMI_RH_NV_INDEX ekCertIndex,
    const char* endorsementPw,
    TPM_HANDLE *ekKeyHandle,
    TPMT_PUBLIC *tpmtPublicOut);

static TPM_RC generateAesKey(TPM2B_DIGEST *encryptionKey);

static TPM_RC compareSecret(TPM2B_DIGEST *secret, 
    TPM2B_DIGEST *decryptedSecret);

static TPM_RC trustiphi_createSrk(TSS_CONTEXT *tssContext, 
    const char* OwnerPw, TPM_HANDLE *handle);

static TPM_RC trustiphi_persistSrk(TSS_CONTEXT *tssContext, 
    TPM_HANDLE srkHandle, const char* OwnerPw);

static TPM_RC trustiphi_processCreatePrimary(TSS_CONTEXT *tssContext,
    TPM_HANDLE *keyHandle,
    TPMI_RH_NV_INDEX ekCertIndex,
    unsigned char *nonce,
    uint16_t nonceSize,
    TPMT_PUBLIC *tpmtPublicIn,
    TPMT_PUBLIC *tpmtPublicOut,
    unsigned int noFlush,
    int print,
    const char* endorsementPw);

static TPM_RC trustiphi_generateCredentialBlob(TSS_CONTEXT *tssContext,
    TPM2B_DIGEST *credential,
    TPMT_PUBLIC *attestPub,
    TPMT_PUBLIC *ekPub,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret);

static TPM_RC trustiphi_activatecredential(TSS_CONTEXT *tssContext,
    TPM_HANDLE activateHandle,
    TPM_HANDLE keyHandle,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret,
    const char* endorsementPw,
    TPM2B_DIGEST *certInfo);

static TPM_RC trustiphi_makePolicySession(TSS_CONTEXT *tssContext,
    TPM_HANDLE authHandle,
    const char* authPw,
    TPMI_SH_AUTH_SESSION *sessionHandle);

static TPM_RC trustiphi_policySecret(TSS_CONTEXT *tssContext,
    TPMI_DH_ENTITY authHandle,
    TPMI_SH_AUTH_SESSION sessionHandle,
    const char* endorsementPw);

static void printUsage();

int vverbose =0;
int verbose = 0;

int main(int argc, char* argv[])
{
    TPM_RC rc = 0;
    TPM_RC rc1 = 0;
    int	i; /* argc iterator */
    TSS_CONTEXT  *tssContext = NULL;
    /* EK cert index */
    TPMI_RH_NV_INDEX ekCertIndex = EK_CERT_RSA_INDEX;   /* default rsa */
    /* EK validation method: 1: make/activate credential; 2: salted session */
    int ekmethod = 2;
    /* CA cert filename*/
    const char *ekcacert = NULL;
    /* EK cert filename */
    const char* ekc = NULL;
    /* output EK cert PEM file */
    const char* ekout = NULL;
    /* Owner auth */
    const char * ownerPw = NULL;
    /* Endorsement auth */
    const char* endorsementPw = NULL;
    /* EK handle */
    TPM_HANDLE ekKeyHandle = 0;
    /* EK public */
    TPMT_PUBLIC ekPub;

    /* command line argument defaults */
    for (i = 1; (i < argc) && (rc == 0); i++) {
        if (strcmp(argv[i], "-ekcacert") == 0) {
            i++;
            if (i < argc) {
                ekcacert = argv[i];
            }
            else {
                printf("Missing parameter for -ekcacert\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-ekc") == 0) {
            i++;
            if (i < argc) {
                ekc = argv[i];
            }
            else {
                printf("Missing parameter for -ekc\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-ekout") == 0) {
            i++;
            if (i < argc) {
                ekout = argv[i];
            }
            else {
                printf("Missing parameter for -ekout\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-ekindex") == 0) {
            i++;
            if (i < argc) {
                if (strcmp(argv[i], "1") == 0) {
                    ekCertIndex = EK_CERT_RSA_INDEX;
                }
                else if (strcmp(argv[i], "2") == 0)
                {
                    ekCertIndex = EK_CERT_EC_INDEX;
                }
                else {
                    printf("-ekindex is not valid\n");
                    printUsage();
                }
            }
            else {
                printf("Missing parameter for -ekindex\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-ekmethod") == 0) {
            i++;
            if (i < argc) {
                if (strcmp(argv[i], "1") == 0)
                {
                    ekmethod = 1;
                }
                else if (strcmp(argv[i], "2") == 0) {
                    ekmethod = 2;
                }
                else {
                    printf("-ekmethod is not valid\n");
                    printUsage();
                }
            }
            else {
                printf("Missing parameter for -ekmethod\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-endorsementpw") == 0) {
            i++;
            if (i < argc) {
                endorsementPw = argv[i];
            }
            else {
                printf("Missing parameter for -endorsementpw\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-ownerpw") == 0) {
            i++;
            if (i < argc) {
                ownerPw = argv[i];
            }
            else {
                printf("Missing parameter for -ownerpw\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        }
        else {
            printf("\n%s is not a valid option\n", argv[i]);
            printUsage();
        }
    }

    if (ekcacert == NULL) {
        printf("Missing or illegal parameter -ekcacert\n");
        printUsage();
    }

    /* start a TSS context */
    if (rc == 0) {
        rc = TSS_Create(&tssContext);
    }
    /* run in HW TPM */
    if (rc == 0) {
        rc = TSS_SetProperty(tssContext, TPM_INTERFACE_TYPE, "dev");
    }
    /* validate EK cert */
    if (rc == 0) {
        rc1 = validateEkCert(tssContext, &ekCertIndex, ekcacert, ekc, 
            endorsementPw, ekout, &ekKeyHandle, &ekPub);
    }   
    /* validate EK */
    if (ekmethod == 1) {
        /* makecredential and activatecredential*/
        if (verbose) {
            printf("INFO: Verify EK by make/activate credential\n");
        }
        rc = validateEk1(tssContext, ekCertIndex, ownerPw, endorsementPw, 
            &ekKeyHandle, &ekPub);
    }
    else if (ekmethod == 2) {
        /* salted session */
        if (verbose) {
            printf("INFO: Verify EK by salted session\n");
        }
        rc = validateEk2(tssContext, ekCertIndex, endorsementPw, &ekKeyHandle);
    }
    if (rc == 0)
    {
        printf("INFO: EK verification success\n");
    }
    /* delete TSS context*/
    {
        TPM_RC rc1 = TSS_Delete(tssContext);
        tssContext = NULL;
        if (rc == 0) {
            rc = rc1;
        }
    }
    if (rc == 0 && rc1 != 0)
    {
        rc = rc1;
    }

    return rc;
}

/* pinrtUsage()
*/
static void printUsage()
{
    printf("\n");
    printf("getAndVerifyEK  -ekcacert <filename> [-ekc <filename>] "
        "[-ekout <filename>] [-ekindex <1 | 2>] [-ekmehod <1 | 2>] "
        "[-endorsementpw <password>] [-ownerpw <password>] [-v]\n");
    printf("\n");
    printf("-ekcacert <filename>  where the file contains a list of filenames of CA certificates\n");
    printf("                      (including the root and intermeidate ones) for the EK certificate\n");
    printf("-ekc <filename>       where the file contains the EK certificate\n");
    printf("-ekout <filename>     where filename is the name of the output EK Cert PEM file\n");
    printf("-ekindex <1 | 2>      The built-in EK certificate \"index\" indicating which EK certificate\n");
    printf("                      in the NV to use, RSA, or ECC. 1 for RSA and 2 for ECC.\n");
    printf("                      This is not a required option. If not included on the command line,\n");
    printf("                      the code will attempt to use RSA and if not found will use ECC.\n");
    printf("-ekmethod <1 | 2>     Indicates which method will be used for TPM validation.\n");
    printf("                      In method 1, a make credential and activate credential are performed,\n");
    printf("                      while in method 2, a salted session is used. This is not a required option.\n");
    printf("                      If not included on the command line, method 2 will be used.\n");
    printf("-endorsementpw        password for endorsement auth\n");
    printf("-ownerpw              password for owner auth\n");
    printf("-v                    verbose mode\n");

    exit(1);
}

/* ekCertToX509()
Convert EK cert string to X509 structure.
@param[in] EK cert binary
@param[in] EK cert length
@param[out] EK cert X509 structure
*/
static TPM_RC ekCertToX509(unsigned char *ekCertificate, 
    uint16_t ekCertLength,
    X509 **ekX509Certificate)    /* freed by caller */
{
    TPM_RC rc = 0;

    /* unmarshal the EK certificate DER stream to 
    EK certificate X509 structure */
    if (rc == 0) {
        /* temp because d2i moves the pointer */
        unsigned char *tmpCert = ekCertificate;
        *ekX509Certificate = d2i_X509(NULL, /* freed by caller */
            (const unsigned char **)&tmpCert, ekCertLength);
        if (*ekX509Certificate == NULL) {
            printf("ERROR: Could not parse X509 EK certificate\n");
            rc = ACE_INVALID_CERT;
        }
    }
    return rc;
}

/* validateEkCertRoot()
Validate the EK certificate against the root
@param[in] EK cert X509 structure
@param[in] filename of the list of CA certs
*/
static TPM_RC validateEkCertRoot(X509 **ekX509Certificate,
    const char *listFilename)
{
    TPM_RC rc = 0;
    char *rootFilename[MAX_ROOTS];
    unsigned int rootFileCount = 0;
    X509_STORE *caStore = NULL;
    X509 *caCert[MAX_ROOTS];
    X509_STORE_CTX *verifyCtx = NULL;
    unsigned int i = 0;

    /* for free */
    for (i = 0; i < MAX_ROOTS; i++) {
        caCert[i] = NULL;
        rootFilename[i] = NULL;
    }
    /* get a list of TPM vendor EK root certificates */
    if (rc == 0) {
        rc = getRootCertificateFilenames(rootFilename,	/* freed @1 */
            &rootFileCount,
            listFilename, 0);
    }
    if ((rc == 0) && vverbose) {
        for (i = 0; i < rootFileCount; i++) {
            printf("INFO: CA cert file name %u\n%s\n", i, rootFilename[i]);
        }
    }
    /* pack the TPM vendor EK root certificates 
    into an openssl certificate store */
    if (rc == 0) {
        rc = getCaStore(&caStore,		/* freed @2 */
            caCert,			/* freed @3 */
            (const char **)rootFilename,
            rootFileCount);
    }
    /* validate the EK certificate against the root */
    if (rc == 0) {
        if (verbose)
            printf("INFO: Validate the client EK certificate against the CA "
            "certificate\n");
    }
    /* create the certificate verify context */
    if (rc == 0) {
        verifyCtx = X509_STORE_CTX_new();
        if (verifyCtx == NULL) {
            printf("ERROR: X509_STORE_CTX_new failed\n");
            rc = ASE_OUT_OF_MEMORY;
        }
    }
    /* add the root certificate store and EK certificate to be verified to 
    the verify context */
    if (rc == 0) {
        int irc = X509_STORE_CTX_init(verifyCtx,    /* freed @4 */
            caStore, *ekX509Certificate, NULL);
        if (irc != 1) {
            printf("ERROR: Error in X509_STORE_CTX_init initializing "
                "verify context\n");
            rc = ASE_OSSL_X509;
        }
    }
    /* walk the TPM EK certificate chain */
    if (rc == 0) {
        int irc = X509_verify_cert(verifyCtx);
        if (irc != 1) {
            printf("ERROR: Error in X590_verify_cert verifying certificate\n");
            rc = ACE_INVALID_CERT;
        }
        else {
            printf("INFO: EK certificate verification success\n");
        }
    }
    for (i = 0; i < rootFileCount; i++) {
        free(rootFilename[i]);	   	/* @1 */
    }
    if (caStore != NULL) {
        X509_STORE_free(caStore);  /* @2 */
    }
    for (i = 0; i < rootFileCount; i++) {
        if (caCert[i] != NULL) {
            X509_free(caCert[i]);	   	/* @3 */
        }
    }
    if (verifyCtx != NULL) {
        X509_STORE_CTX_free(verifyCtx); /* @4 */
    }
        
    return rc;
}

/* validateEkCert()
Read EK cert from NV/input file.
Validate EK cert against the EK cert CA cert.
If input EK cert is not NULL, validate it;
else, validate the EK cert in NV.
If output EK cert filename is not NULL,
output EK cert in TPM (pem).
Create EK in TPM and compare EK with the one in EK cert.
@param[in] TSS context
@param[in] EK cert index (RSA or ECC)
@param[in] EK cert CA cert (pem)
@param[in] EK cert (pem) from input file
@param[in] endorsement auth password
@param[in] output EK cert filename
@param[out] EK handle
@param[out] EK public
*/
static TPM_RC validateEkCert(TSS_CONTEXT *tssContext,
    TPMI_RH_NV_INDEX *ekCertIndex,
    const char *ekcacert,
    const char *ekc,
    const char *endorsementPw,
    const char *ekout,
    TPM_HANDLE *ekKeyHandle,
    TPMT_PUBLIC *ekPub)
{
    TPM_RC rc = 0;
    TPM_RC rc1 = 0;
    TPM_RC rc2 = 0;
    int flag = 0;
    unsigned char *ekCertificate = NULL;
    uint16_t ekCertLength;
    /* ek cert from input */
    X509 *ekX509Certificate1 = NULL;
    /* ek cert from NV */
    X509 *ekX509Certificate2 = NULL;
    FILE *pemFile = NULL;

    if (ekc != NULL) {
        /* input EK cert */
        if (rc == 0) {
            /* read EK cert to x509 structure */
            if (verbose) {
                printf("INFO: Read EK cert from input PEM file\n");
            }
            rc = readEkCert(ekc, &ekX509Certificate1);   /* freed @1 */
        }
        if (rc == 0) {
            /* get EK cert index */
            if (verbose) {
                printf("INFO: Get index type of input EK cert\n");
            }
            rc = getCertType(&ekX509Certificate1, ekCertIndex);
        }
        if (rc != 0) {
            printf("ERROR: Read EK cert from file fail, "
                "try to read EK cert in NV\n");
        }
        else {
            /* indicate EK from input file is used in validation */
            flag = 1;
        }
    }
    if (ekc == NULL || rc != 0 || ekout != NULL) {
        /* read the TPM EK certificate from TPM NV */
        if (verbose) {
            printf("INFO: Read EK cert from NV\n");
        }
        rc = getIndexContents(tssContext,
            &ekCertificate,		/* freed @2 */
            &ekCertLength,		/* total size read */
            *ekCertIndex);			/* RSA or EC */
        if (rc != 0) {
            /* try another type of index */
            if (*ekCertIndex == EK_CERT_RSA_INDEX) {
                *ekCertIndex = EK_CERT_EC_INDEX;
            }
            else if (*ekCertIndex == EK_CERT_EC_INDEX) {
                *ekCertIndex = EK_CERT_RSA_INDEX;
            }
            rc = getIndexContents(tssContext,
                &ekCertificate,		/* freed @2 */
                &ekCertLength,		/* total size read */
                *ekCertIndex);			/* RSA or EC */
        }
        /* convert EK certificate to X509 format */
        if (rc == 0) {
            if (verbose) {
                printf("INFO: Convert EK cert to X509 format\n");
            }
            rc = ekCertToX509(ekCertificate, ekCertLength,
                &ekX509Certificate2);    /* freed @3 */
        }
        free(ekCertificate); /* @2 */
        if (rc != 0)
        {
            printf("ERROR: Read EK cert from NV fail\n");
        }
    }
    /* write EK cert to file */
    if (rc == 0 && ekout != NULL && ekX509Certificate2 != NULL) {
        if (verbose) {
            printf("INFO: Write EK cert from TPM to file\n");
        }
        pemFile = fopen(ekout, "wb");
        if (pemFile == NULL) {
            printf("ERROR: Unable to open PEM file %s for write\n", 
                ekout);
            rc1 = TSS_RC_FILE_OPEN;
        }
        else {
            rc1 = 1 - PEM_write_X509(pemFile, ekX509Certificate2);
            fclose(pemFile);
        }
    }
    /* validate EK cert against CA cert */
    if (rc == 0) {
        if (flag) {
            /* validate ek cert from input */
            rc2 = validateEkCertRoot(
                &ekX509Certificate1,
                ekcacert);
        }
        else {
            /* validate ek cert in TPM */
            rc2 = validateEkCertRoot(
                &ekX509Certificate2,
                ekcacert);
        }
    }
    /* compare EK pub in TPM and the one in EK cert */
    if (rc == 0) {
        if (verbose) {
            printf("INFO: Compare EK in EK cert and EK in TPM\n");
        }
        /* Create EK and get EK pub */
        if (rc == 0) {
            rc = createEkPrimary(tssContext, *ekCertIndex, 
                endorsementPw,
                ekKeyHandle,
                ekPub);
        }
        /* compare keys */
        if (rc == 0) {
            if (flag) {
                /* compare Ek in EK cert from input and EK in TPM */
                rc = compareEkPub(ekPub, &ekX509Certificate1);
            }
            else {
                /* compare EK in EK cert from and EK in TPM */
                rc = compareEkPub(ekPub, &ekX509Certificate2);
            }
        }
        if (rc == 0) {
            printf("INFO: Compare EK in EK cert and EK in TPM "
                "success\n");
        }
        else {
            printf("ERROR: Compare EK in EK cert and EK in TPM "
                "fails\n");
        }
    }
    if (ekX509Certificate1 != NULL) {
        X509_free(ekX509Certificate1);   /* @1 */
    }
    if (ekX509Certificate2 != NULL) {
        X509_free(ekX509Certificate2);   /* @3 */
    }
    if (rc == 0 && rc1 != 0) {
        rc = rc1;
    }
    else if (rc == 0 && rc2 != 0) {
        rc = rc2;
    }

    return rc;
}

/* readEkCert()
Read a EK certificate file in PEM format to X.509 c structure.
@param[in] EK certificate file in PEM format
@param[out] EK certificate X.509 c structure
*/
static TPM_RC readEkCert(const char* filename, X509 **ekX509Certificate)
{
    TPM_RC rc = 0;
    FILE *pemFile = fopen(filename, "rb");
    if (pemFile == NULL) {
        printf("ERROR: Unable to open PEM file %s\n", filename);
        rc = TSS_RC_FILE_OPEN;
    }
    else {
        X509 *ret = PEM_read_X509(pemFile, ekX509Certificate, NULL, NULL);
        if (ret == NULL) {
            printf("ERROR: Unable to read PEM file %s to X509 structure\n", 
                filename);
            rc = 1;
        }
        fclose(pemFile);
    }   
    return rc;
}

/* getCertType()
Get the type of EK cert: RSA or ECC.
@param[in] EK cert in X509 structure 
@param[out] EK cert type
*/
static TPM_RC getCertType(X509 **ekX509Certificate, 
    TPMI_RH_NV_INDEX *ekCertIndex)
{
    TPM_RC rc = 0;
    EVP_PKEY *pkey = NULL;
    int pkeyType;

    pkey = X509_get_pubkey(*ekX509Certificate);
    if (pkey == NULL) {
        printf("ERROR: Could not extract public key from X509 certificate\n");
        rc = ACE_INVALID_CERT;
    }
    if (rc == 0)
    {
        pkeyType = getRsaPubkeyAlgorithm(pkey);
        if (pkeyType == EVP_PKEY_RSA) {
            *ekCertIndex = EK_CERT_RSA_INDEX;
        }
        else if (pkeyType == EVP_PKEY_EC) {
            *ekCertIndex = EK_CERT_EC_INDEX;
        }
        else {
            printf("ERROR: EK Public key is not RSA or EC\n");
            rc = ACE_INVALID_CERT;
        }
    }
    EVP_PKEY_free(pkey);

    return rc;
}

/* compareEkPub()
Compare the EK pub generated from TPM with the one in the EK certifiate.
Retrun 0 if they are the same.
@param[in] EK pub generated from TPM
@param[in] EK certificate in X.509 c structure
*/
static TPM_RC compareEkPub(TPMT_PUBLIC *ekPub, X509 **ekX509Certificate)
{
    TPM_RC rc = 0;
    /* EK Pub from EK cert */
    EVP_PKEY *pkey1 = NULL;
    /* EK Pub from TPM */
    EVP_PKEY *pkey2 = NULL;

    /* get public key from EK cert */     
    if (rc == 0) {
        pkey1 = X509_get_pubkey(*ekX509Certificate); /* freed @1 */
        if (pkey1 == NULL) {
            printf("ERROR: Could not extract public key from X509 "
                "certificate\n");
            rc = ACE_INVALID_CERT;
        }
    }
    /* for EK pub from TPM, construct EVP_PKEY from TPMT_PUBLIC */
    if (rc == 0)
    {
        switch (ekPub->type) {
        case TPM_ALG_RSA:
            rc = convertRsaPublicToEvpPubKey(&pkey2,	/* freed @2 */
               &ekPub->unique.rsa);
            break;
        case TPM_ALG_ECC:
            rc = convertEcPublicToEvpPubKey(&pkey2,		/* freed @2 */
                &ekPub->unique.ecc);
            break;
        default:
            rc = TSS_RC_NOT_IMPLEMENTED;
            break;
        }
    }
    if (rc == 0)
    {
        rc = EVP_PKEY_cmp(pkey1, pkey2);
        if (rc == 1)
        {
            rc = 0;
        }
        else {
            rc = 1;
        }
    }
    EVP_PKEY_free(pkey1);    /* @1 */
    EVP_PKEY_free(pkey2);    /* @2 */

    return rc;
}

/* validateEk1()
Create SRK if it does not exsit.
Create attestation key.
Create EK.
Generate a random AES key (secret).
Run makecredential to wrap the secret with the EK pub (SW TPM).
Run activatecredential to decrypt the secret with EK.
@param[in] TSS context
@param[in] EK cert index (RSA or ECC)
@param[in] owner auth password
@param[in] endorsement auth password
@param[in] EK handle
@param[in] EK public
*/
static TPM_RC validateEk1(TSS_CONTEXT *tssContext, 
    TPMI_RH_NV_INDEX ekCertIndex, 
    const char *ownerPw, const char *endorsementPw, 
    TPM_HANDLE *ekKeyHandle, TPMT_PUBLIC *ekPub)
{
    TPM_RC rc = 0;
    int exists = 0; /* flag, true if SRK exists */
    TPM_HANDLE 	srkHandle;	/* the loaded SRK transient handle */
    TPM2B_PRIVATE attestPriv;
    TPM2B_PUBLIC attestPub;
    uint16_t attestPubLength;
    unsigned char *attestPubBin = NULL;
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
    TPM2B_DIGEST encryptionKey;	/* AES key */
    TPM2B_DIGEST certInfo;	/* dycrypted  AES key */
    const char *swTpmDir = "sw_tpm_data"; /* data dir of SW TPM */

    if (verbose) {
        printf("INFO: Create attestation key under SRK\n");
    }
    /* does the SRK already exist */
    if (rc == 0) {
        rc = getCapSrk(tssContext, &exists);
    }
    /* create the primary SRK if it does not exist */
    if ((rc == 0) && !exists) {
        //rc = createSrk(tssContext, &srkHandle);
        rc = trustiphi_createSrk(tssContext, ownerPw, &srkHandle);
    }
    /* make the SRK persistent in the TPM */
    if ((rc == 0) && !exists) {
        //rc = persistSrk(tssContext, srkHandle);
        rc = trustiphi_persistSrk(tssContext, srkHandle, ownerPw);
    }
    /* flush the transient copy of the SRK */
    if ((rc == 0) && !exists) {
        rc = flushContext(tssContext, srkHandle);
    }
    /* Create the attestation signing key under the primary key */
    if (rc == 0) {
        rc = createAttestationKey(tssContext,
            ekCertIndex,    /* RSA or EC */
            &attestPriv,
            &attestPub,
            &attestPubLength,
            &attestPubBin); /* freed @1 */
    }
    free(attestPubBin); /* @1 */
    /* generate a random AES-256 key */
    if (rc == 0) {
        if (verbose) {
            printf("INFO: Generate a random AES-256 key as secret\n");
        }
        rc = generateAesKey(&encryptionKey);
    }
    /* make credential in SW TPM */
    /* create data dir for SW TPM */
    if (rc == 0) {
        char cmd[80];
        strcpy(cmd, "mkdir ");
        strcat(cmd, swTpmDir);
        system(cmd);
    }
    if (rc == 0) {
        TSS_CONTEXT *tssContext1 = NULL;
        if (verbose) {
            printf("INFO: Make credential in SW TPM\n");
        }
        if (rc == 0) {
            rc = TSS_Create(&tssContext1);
        }
        /* run in SW TPM */
        if (rc == 0) {
            rc = TSS_SetProperty(tssContext1, TPM_INTERFACE_TYPE, 
                "socsim");
        }
        /* set different directory for SW TPM */        
        if (rc == 0) {
            TSS_SetProperty(tssContext1, TPM_DATA_DIR, swTpmDir);
        }
        if (rc == 0) {
            rc = trustiphi_generateCredentialBlob(tssContext1,
                &encryptionKey,
                &(attestPub.publicArea),
                ekPub,
                &credentialBlob,
                &secret);
        }
        {
            TPM_RC rc1 = TSS_Delete(tssContext1);
            tssContext1 = NULL;
            if (rc == 0) {
                rc = rc1;
            }
        }
        /* remove TPM data folder */
        if (rc == 0) {
            char cmd[80];
#ifdef __linux__
            strcpy(cmd, "rm -rf ");
#elif _WIN32
            strcpy(cmd, "rd /s/q ");
#endif
            strcat(cmd, swTpmDir);
            system(cmd);
        }
    }
    /* activate credential */
    if (rc == 0) {
        TPMI_DH_OBJECT activateHandle = 0;
        /* load attestation key */
        if (rc == 0) {
            rc = loadAttestationKey(tssContext,
                &activateHandle,	/* flushed @2 */
                &attestPriv,
                &attestPub);
        }
        if (rc == 0) {
            if (verbose) {
                printf("INFO: Activate credential\n");
            }
            rc = trustiphi_activatecredential(tssContext,
                activateHandle, /* loaded key */
                *ekKeyHandle,  /* loaded EK */
                &credentialBlob,
                &secret,
                endorsementPw,
                &certInfo);
        }
        /* flush the attestation key */
        if (activateHandle != 0) {
            if (verbose) printf("INFO: Flush attestation key %08x\n",
                activateHandle);
            TPM_RC rc1 = flushContext(tssContext, 
                activateHandle);	/* @2 */
            if (rc == 0) {
                rc = rc1;
            }
        }
        /* flush the primary key */
        if (*ekKeyHandle != 0) {
            if (verbose) printf("INFO: Flush EK %08x\n",
                *ekKeyHandle);
            TPM_RC rc1 = flushContext(tssContext, *ekKeyHandle);
            if (rc == 0) {
                rc = rc1;
            }
        }
    }
    /* compare the decrypted secret with the original one */
    if (rc == 0) {
        if (verbose) {
            printf("INFO: Compare decrypted secret "
                "and original secret\n");
        }
        rc = compareSecret(&encryptionKey, &certInfo);
    }

    return rc;
}

/* Create EK and get handle.
Create a policy session salted with EK.
Run plocySecret to satisfy the EK policy.
Create a signing key under EK.
Flush the policy session.
Flush EK.
@param[in] TSS context
@param[in] EK cert index (RSA or ECC)
@param[in] endorsement auth password
@param[in] EK handle
*/
static TPM_RC validateEk2(TSS_CONTEXT *tssContext, 
    TPMI_RH_NV_INDEX ekCertIndex, 
    const char *endorsementPw,
    TPM_HANDLE *ekKeyHandle)
{
    TPM_RC rc = 0;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    int pwSession = FALSE;  /* default HMAC session */
    TPMI_SH_AUTH_SESSION policySessionHandle = TPM_RH_NULL;

    /* start a policy session */
    if (rc == 0) {
        TPM_HANDLE saltHandle;
        if (verbose) printf("INFO: Start a policy session\n");
        if (!pwSession) {
            saltHandle = *ekKeyHandle;
        }
        else {
            saltHandle = TPM_RH_NULL;   /* primary key handle */
        }
        rc = startSession(tssContext,
            &policySessionHandle,   /* flushed @1 */
            TPM_SE_POLICY,
            saltHandle, TPM_RH_NULL,    /* salt, no bind */
            NULL);  /* no bind password */
        if (verbose) printf("INFO: Policy session %08x\n", 
            policySessionHandle);
    }
    /* EK needs policy secret with endorsement auth */
    if (rc == 0) {
        if (verbose) printf("INFO: Satisfy the policy session %08x\n", 
            policySessionHandle);
        //rc = policySecret(tssContext,
        //    TPM_RH_ENDORSEMENT,
        //    policySessionHandle);
        rc = trustiphi_policySecret(tssContext,
            TPM_RH_ENDORSEMENT,
            policySessionHandle, endorsementPw);
    }
    /* trace the session policy digest for debugging */
    if (rc == 0) {
        if (verbose) printf("INFO: Dump the policy session %08x\n", 
            policySessionHandle);
        rc = policyGetDigest(tssContext,
            policySessionHandle);
    }
    /* create the signing key */
    if (rc == 0) {
        if (verbose) printf(
            "INFO: Create a signing key under the EK %08x\n", 
            *ekKeyHandle);
        rc = createKey(tssContext,
            &outPrivate,
            &outPublic,
            policySessionHandle,    /* continue */
            *ekKeyHandle,    /* parent */
            NULL,   /* password for the signing key */
            pwSession);
    }
    /* flush EK */
    if (*ekKeyHandle != 0) {
        if (verbose) printf("INFO: Flush EK %08x\n",
            *ekKeyHandle);
        TPM_RC rc1 = flushContext(tssContext, *ekKeyHandle);
        if (rc == 0) {
            rc = rc1;
        }
    }
    /* flush the policy session, normally fails */
    if (verbose) printf("INFO: Flush the policy session %08x\n", 
        policySessionHandle);
    flushContext(tssContext, policySessionHandle);  /* @1 */
    if (rc == 0) {
        if (verbose) printf("INFO: Create signing key: Success\n");
    }

    return rc;
}

/* createEkPrimary()
Create EK primary key.
Get handle for EK primary key.
@param[in] TSS context
@param[in] EK cert index (RSA or ECC)
@param[in] endorsement auth password
@param[out] handle for EK primary key
@param[out] EK pub
*/
static TPM_RC createEkPrimary(TSS_CONTEXT *tssContext,
    TPMI_RH_NV_INDEX ekCertIndex,
    const char* endorsementPw,
    TPM_HANDLE *ekKeyHandle,
    TPMT_PUBLIC *tpmtPublicOut)
{
    TPM_RC rc = 0;
    /* get the EK nonce, if it exists */
    unsigned char *nonce = NULL;
    uint16_t nonceSize;
    TPMI_RH_NV_INDEX ekNonceIndex;
    TPMI_RH_NV_INDEX ekTemplateIndex;
    TPMT_PUBLIC tpmtPublicIn;   /* template */

    if (verbose) {
        printf("INFO: Create EK primary in TPM\n");
    }
    if (rc == 0) {
        if (ekCertIndex == EK_CERT_RSA_INDEX) {
            ekNonceIndex = EK_NONCE_RSA_INDEX;
            ekTemplateIndex = EK_TEMPLATE_RSA_INDEX;
        }
        else if (ekCertIndex == EK_CERT_EC_INDEX) {
            ekNonceIndex = EK_NONCE_EC_INDEX;
            ekTemplateIndex = EK_TEMPLATE_EC_INDEX;
        }
        else {
            if (verbose) printf("ERROR: Algoritm in EK cert is not "
                "supported\n");
            rc = TPM_RC_VALUE;
        }
    }
    if (rc == 0) {
        rc = processEKNonce(tssContext,
            &nonce, /* freed @1 */
            &nonceSize,
            ekNonceIndex,
            vverbose);
        if ((rc & 0xff) == TPM_RC_HANDLE) {
            if (verbose) printf("INFO: EK nonce not found, use default "
                "template\n");
            rc = 0;
        }
    }
    if (rc == 0) {
        /* if the nonce was found, get the EK template.  */
        if (nonce != NULL) {
            rc = processEKTemplate(tssContext, 
                &tpmtPublicIn, ekTemplateIndex, vverbose);
        }
    }
    /* create the primary key. nonce NULL indicates that the default IWG
    template should be used.  */
    if (rc == 0) {
        //rc = processCreatePrimary(tssContext,
        //    ekKeyHandle,    /* loaded EK handle */
        //    ekCertIndex,    /* RSA or ECC algorithm */
        //    nonce, nonceSize,   /* EK nonce, can be NULL */
        //    &tpmtPublicIn,  /* template */
        //    tpmtPublicOut, /* primary key */
        //    TRUE,   /* noFlush */
        //    vverbose);  /* print errors */
        rc = trustiphi_processCreatePrimary(tssContext,
            ekKeyHandle,    /* loaded EK handle */
            ekCertIndex,    /* RSA or ECC algorithm */
            nonce, nonceSize,   /* EK nonce, can be NULL */
            &tpmtPublicIn,  /* template */            
            tpmtPublicOut, /* primary key */
            TRUE,   /* noFlush */
            vverbose,
            endorsementPw);  /* print errors */
    }
    free(nonce);    /* @1 */
    return rc;
}

/* generateAesKey()
Generate a random AES-256 key.
@param[out] a rabdom AES-256 key
*/
static TPM_RC generateAesKey(TPM2B_DIGEST *encryptionKey)
{
    TPM_RC rc = 0;
    int irc = 0;
    if (rc == 0) {
        encryptionKey->t.size = 256 / 8;
        irc = RAND_bytes(encryptionKey->t.buffer, 256 / 8);
        if (irc != 1) {
            printf("ERROR: Random number generation failed\n");
            rc = ASE_OSSL_RAND;
        }
    }
    return rc;
}

/*compareSecret()
Compare the decrypted secret with the original one.
@param[in] origianl secret
@param[in] decrypted secret
*/
static TPM_RC compareSecret(TPM2B_DIGEST *secret, 
    TPM2B_DIGEST *decryptedSecret) 
{
    TPM_RC rc = 0;
    char *secretString = NULL;
    char *decryptedSecretString = NULL;

    Array_PrintMalloc(&secretString, secret->t.buffer, secret->t.size);
    Array_PrintMalloc(&decryptedSecretString, decryptedSecret->t.buffer, 
        decryptedSecret->t.size);
    if (strcmp(secretString, decryptedSecretString) != 0) {
        printf("ERROR: Decrypted secret is not correct\n");
        rc = 1;
    }
    else if (verbose) {
        printf("INFO: Decrypted secret is correct\n");
    }
    free(secretString);
    free(decryptedSecretString);
    return rc;
}

/* trustiphi_createSrk()
Create a storage primary key (SRK) in the owner hierarchy.
@param[in] TSS context
@param[in] Owner auth password
@param[out] key handle for SRK
*/
static TPM_RC trustiphi_createSrk(TSS_CONTEXT *tssContext, 
    const char* OwnerPw, TPM_HANDLE *handle)
{
    TPM_RC			rc = 0;
    CreatePrimary_In 		in;
    CreatePrimary_Out 		out;

    /* set up the createprimary in parameters */
    if (rc == 0) {
        in.primaryHandle = TPM_RH_OWNER;
        in.inSensitive.sensitive.userAuth.t.size = 0;
        in.inSensitive.sensitive.data.t.size = 0;
        /* creation data */
        in.outsideInfo.t.size = 0;
        in.creationPCR.count = 0;
        in.inPublic.publicArea.type = TPM_ALG_RSA;
        in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
        in.inPublic.publicArea.objectAttributes.val = TPMA_OBJECT_NODA |
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_DECRYPT |
            TPMA_OBJECT_RESTRICTED;
        in.inPublic.publicArea.authPolicy.t.size = 0;
        in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = 
            TPM_ALG_AES;
        in.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 
            128;
        in.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = 
            TPM_ALG_CFB;
        in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = 
            TPM_ALG_NULL;
        in.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig
            .hashAlg = 0;
        in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        in.inPublic.publicArea.unique.rsa.t.size = 0;
        in.outsideInfo.t.size = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&out,
            (COMMAND_PARAMETERS *)&in,
            NULL,
            TPM_CC_CreatePrimary,
            TPM_RS_PW, OwnerPw, 0,
            TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
        if (vverbose) printf("createSrk: Handle %08x\n", out.objectHandle);
        *handle = out.objectHandle;
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("ERROR: createSrk: failed, rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}

/* trustiphi_persistSrk()
Make a copy of the SRK in TPM non-volatile memory.
The transient copy is not flushed.
@param[in] TSS context
@param[in] key handle for SRK
@param[in] Owner auth password
*/
static TPM_RC trustiphi_persistSrk(TSS_CONTEXT *tssContext, 
    TPM_HANDLE srkHandle, const char* OwnerPw)
{
    TPM_RC			rc = 0;
    EvictControl_In 		in;

    if (rc == 0) {
        in.auth = TPM_RH_OWNER;
        in.objectHandle = srkHandle;
        in.persistentHandle = SRK_HANDLE;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            NULL,
            (COMMAND_PARAMETERS *)&in,
            NULL,
            TPM_CC_EvictControl,
            TPM_RS_PW, OwnerPw, 0,
            TPM_RH_NULL, NULL, 0);
        if (rc == 0) {
            if (vverbose) 
                printf("INFO: persistSrk: TPM2_EvictControl success\n");
        }
        else {
            const char *msg;
            const char *submsg;
            const char *num;
            printf("ERROR: evictcontrol: failed, rc %08x\n", rc);
            TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
            printf("%s%s%s\n", msg, submsg, num);
            rc = EXIT_FAILURE;
        }
    }
    return rc;
}

/* trustiphi_processCreatePrimary()
Combine the EK nonce and EK template from NV to form the createprimary input.
It creates the primary key.
ekCertIndex determines whether an RSA or ECC key is created.
If nonce is NULL, the default IWG templates are used.
If nonce is non-NULL, the nonce and tpmtPublicIn are used.
After returning the TPMT_PUBLIC, flush the primary key unless noFlush is TRUE.
If noFlush is FALSE, returns the loaded handle, else returns TPM_RH_NULL.
@param[in] TSS context
@param[in] EK cert index
@param[in] nonce
@param[in] nonce size
@param[in] EK template
@param[in] endorsement auth password
@param[out] key handle for EK primary
@param[out] EK primary key pubic part
*/
static TPM_RC trustiphi_processCreatePrimary(TSS_CONTEXT *tssContext,
    TPM_HANDLE *keyHandle,		/* primary key handle */
    TPMI_RH_NV_INDEX ekCertIndex,
    unsigned char *nonce,
    uint16_t nonceSize,
    TPMT_PUBLIC *tpmtPublicIn,		/* template */
    TPMT_PUBLIC *tpmtPublicOut,		/* primary key */
    unsigned int noFlush,	/* TRUE - don't flush the primary key */
    int print,
    const char* endorsementPw)
{
    TPM_RC			rc = 0;
    CreatePrimary_In 		inCreatePrimary;
    CreatePrimary_Out 		outCreatePrimary;

    /* set up the createprimary in parameters */
    if (rc == 0) {
        inCreatePrimary.primaryHandle = TPM_RH_ENDORSEMENT;
        inCreatePrimary.inSensitive.sensitive.userAuth.t.size = 0;
        inCreatePrimary.inSensitive.sensitive.data.t.size = 0;
        /* creation data */
        inCreatePrimary.outsideInfo.t.size = 0;
        inCreatePrimary.creationPCR.count = 0;
    }
    /* construct the template from the NV template and nonce */
    if ((rc == 0) && (nonce != NULL)) {
        inCreatePrimary.inPublic.publicArea = *tpmtPublicIn;
        if (ekCertIndex == EK_CERT_RSA_INDEX) {			/* RSA primary key */
            /* unique field is 256 bytes */
            inCreatePrimary.inPublic.publicArea.unique.rsa.t.size = 256;
            /* first part is nonce */
            memcpy(inCreatePrimary.inPublic.publicArea.unique.rsa.t.buffer, 
                nonce, nonceSize);
            /* padded with zeros */
            memset(inCreatePrimary.inPublic.publicArea.unique.rsa.t.buffer 
                + nonceSize, 0, 256 - nonceSize);
        }
        else {							/* EC primary key */
            /* unique field is X and Y points */
            /* X gets nonce and pad */
            inCreatePrimary.inPublic.publicArea.unique.ecc.x.t.size = 32;
            memcpy(inCreatePrimary.inPublic.publicArea.unique.ecc.x.t.buffer, 
                nonce, nonceSize);
            memset(inCreatePrimary.inPublic.publicArea.unique.ecc.x.t.buffer 
                + nonceSize, 0, 32 - nonceSize);
            /* Y gets zeros */
            inCreatePrimary.inPublic.publicArea.unique.ecc.y.t.size = 32;
            memset(inCreatePrimary.inPublic.publicArea.unique.ecc.y.t.buffer, 
                0, 32);
        }
    }
    /* construct the template from the default IWG template */
    if ((rc == 0) && (nonce == NULL)) {
        if (ekCertIndex == EK_CERT_RSA_INDEX) {			/* RSA primary key */
            getRsaTemplate(&inCreatePrimary.inPublic.publicArea);
        }
        else {							/* EC primary key */
            getEccTemplate(&inCreatePrimary.inPublic.publicArea);
        }
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&outCreatePrimary,
            (COMMAND_PARAMETERS *)&inCreatePrimary,
            NULL,
            TPM_CC_CreatePrimary,
            TPM_RS_PW, endorsementPw, 0,
            TPM_RH_NULL, NULL, 0);
        if (rc != 0) {
            const char *msg;
            const char *submsg;
            const char *num;
            printf("createprimary: failed, rc %08x\n", rc);
            TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
            printf("%s%s%s\n", msg, submsg, num);
        }
    }
    /* return the primary key */
    if (rc == 0) {
        *tpmtPublicOut = outCreatePrimary.outPublic.publicArea;
    }
    /* flush the primary key */
    if (rc == 0) {
        if (print) printf("Primary key Handle %08x\n", 
            outCreatePrimary.objectHandle);
        if (!noFlush) {		/* flush the primary key */
            *keyHandle = TPM_RH_NULL;
            FlushContext_In 		inFlushContext;
            inFlushContext.flushHandle = outCreatePrimary.objectHandle;
            rc = TSS_Execute(tssContext,
                NULL,
                (COMMAND_PARAMETERS *)&inFlushContext,
                NULL,
                TPM_CC_FlushContext,
                TPM_RH_NULL, NULL, 0);
            if (rc != 0) {
                const char *msg;
                const char *submsg;
                const char *num;
                printf("flushcontext: failed, rc %08x\n", rc);
                TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
                printf("%s%s%s\n", msg, submsg, num);
            }
        }
        else {	/* not flushed, return the handle */
            *keyHandle = outCreatePrimary.objectHandle;
        }
    }
    /* trace the public key */
    if (rc == 0) {
        if (ekCertIndex == EK_CERT_RSA_INDEX) {
            if (print) TSS_PrintAll("createprimary: RSA public key",
                outCreatePrimary.outPublic.publicArea.unique.rsa.t.buffer,
                outCreatePrimary.outPublic.publicArea.unique.rsa.t.size);
        }
        else {
            if (print) TSS_PrintAll("createprimary: ECC public key x",
                outCreatePrimary.outPublic.publicArea.unique.ecc.x.t.buffer,
                outCreatePrimary.outPublic.publicArea.unique.ecc.x.t.size);
            if (print) TSS_PrintAll("createprimary: ECC public key y",
                outCreatePrimary.outPublic.publicArea.unique.ecc.y.t.buffer,
                outCreatePrimary.outPublic.publicArea.unique.ecc.y.t.size);
        }
    }
    return rc;
}

/* trustiphi_generateCredentialBlob()
Load attestation key pub and calculate the name.
Flush attestion key pub.
Load EK pub.
Run makecredential to wrap the AES key with the EK pub.
Flush EK pub.
@param[in] TSS context
@param[in] AES key (credential)
@param[in] EK pub
@param[in] attestation key pub
@param[out] credential blob
@param[out] encrypted secret
*/
static TPM_RC trustiphi_generateCredentialBlob(TSS_CONTEXT *tssContext,
    TPM2B_DIGEST *credential,
    TPMT_PUBLIC *attestPub,
    TPMT_PUBLIC *ekPub,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret)
{
    TPM_RC rc = 0;
    TPM_HANDLE keyHandle = 0;   /* loaded key handle */
    TPM2B_NAME name;    /* attestation key Name */

    if (vverbose) printf("generateCredentialBlob: Entry\n");
    /* Load the attestation public key. 
    This uses the TPM to calculate the Name. */
    if (rc == 0) {
        rc = loadExternal(tssContext,
            &keyHandle, /* attestation key handle */
            &name,
            attestPub); /* attestation public key */
    }
    /* After the Name is returned, the loaded key is no longer needed. */
    if (keyHandle != 0) {
        rc = flushContext(tssContext,
            keyHandle);
        keyHandle = 0;
    }
    /* load the EK public key, storage key used by makecredential */
    if (rc == 0) {
        rc = loadExternal(tssContext,
            &keyHandle, /* EK handle */
            NULL,   /* don't need the Name */
            ekPub); /* client EK public key */
    }
    /* makecredential, encrypt the secret, etc */
    if (rc == 0) {
        rc = makecredential(tssContext,
            credentialBlob,
            secret,
            keyHandle,
            credential,
            &name);
    }
    /* done with the EK */
    if (keyHandle != 0) {
        rc = flushContext(tssContext,
            keyHandle);
    }
    if (rc == 0) {
        if (verbose) printf("INFO: Generated credential blob\n");
    }
    return rc;
}

/* trustiphi_activatecredential()
Run activatecredential to decrypt the secret with EK.
@param[in] TSS context
@param[in] attestation key handle
@param[in] EK handle
@param[in] credential blob
@param[in] encrypted secret
@param[in] endorsement auth password
@param[out] decrypted secret
*/
static TPM_RC trustiphi_activatecredential(TSS_CONTEXT *tssContext,
    TPM_HANDLE activateHandle,  /* loaded key */
    TPM_HANDLE keyHandle,   /* loaded EK */
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret,
    const char* endorsementPw,
    TPM2B_DIGEST *certInfo) /* decrypted secret */
{
    TPM_RC rc = 0;
    ActivateCredential_In in;
    ActivateCredential_Out out;
    TPMI_SH_AUTH_SESSION sessionHandle;

    if (rc == 0) {
        in.activateHandle = activateHandle;
        in.keyHandle = keyHandle;
        in.credentialBlob = *credentialBlob;
        in.secret = *secret;
    }
    /* using the EK requires a policy session */
    if (rc == 0) {
        //rc = makePolicySession(tssContext,
        //    &sessionHandle);
        rc = trustiphi_makePolicySession(tssContext, TPM_RH_ENDORSEMENT, 
            endorsementPw, &sessionHandle);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&out,
            (COMMAND_PARAMETERS *)&in,
            NULL,
            TPM_CC_ActivateCredential,
            TPM_RS_PW, NULL, 0,
            sessionHandle, NULL, 0,
            TPM_RH_NULL, NULL, 0);
        if (rc == 0) {
            *certInfo = out.certInfo;
            if (vverbose) TSS_PrintAll("activatecredential: decrypted secret:",
                out.certInfo.t.buffer, out.certInfo.t.size);
        }
        else {
            flushContext(tssContext, sessionHandle);
            const char *msg;
            const char *submsg;
            const char *num;
            printf("ERROR: activatecredential: failed, rc %08x\n", rc);
            TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
            printf("%s%s%s\n", msg, submsg, num);
            rc = EXIT_FAILURE;
        }
    }
    return rc;
}

/* trustiphi_makePolicySession()
Make a policy session that can be used as an endorsement/owner authorization.
Returns the policy session handle.
@param[in] TSS context
@param[in] auth handle: TPM_RH_ENDORSEMENT or TPM_RH_OWNER
@param[in] auth password
@param[out] policy session handle
*/
static TPM_RC trustiphi_makePolicySession(TSS_CONTEXT *tssContext,
    TPM_HANDLE authHandle,
    const char* authPw,
    TPMI_SH_AUTH_SESSION *sessionHandle)
{
    TPM_RC 			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;
    PolicySecret_In 		policySecretIn;
    PolicySecret_Out 		policySecretOut;

    /* start a policy session */
    if (rc == 0) {
        startAuthSessionIn.sessionType = TPM_SE_POLICY;
        startAuthSessionIn.tpmKey = TPM_RH_NULL;
        startAuthSessionIn.bind = TPM_RH_NULL;
        startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
        startAuthSessionIn.authHash = TPM_ALG_SHA256;
        startAuthSessionIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
        startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
        startAuthSessionExtra.bindPassword = NULL;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&startAuthSessionOut,
            (COMMAND_PARAMETERS *)&startAuthSessionIn,
            (EXTRA_PARAMETERS *)&startAuthSessionExtra,
            TPM_CC_StartAuthSession,
            TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
        *sessionHandle = startAuthSessionOut.sessionHandle;
        if (verbose) 
            printf("INFO: makePolicySession: Policy session handle %08x\n",
            startAuthSessionOut.sessionHandle);
        if (vverbose) 
            printf("makePolicySession: TPM2_StartAuthSession success\n");
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("ERROR: makePolicySession: TPM2_StartAuthSession failed, "
            "rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
        rc = EXIT_FAILURE;
    }
    /* run policy secret over the endorsement auth to satisfy the policy */
    if (rc == 0) {
        policySecretIn.authHandle = authHandle;
        policySecretIn.policySession = startAuthSessionOut.sessionHandle;
        policySecretIn.nonceTPM.b.size = 0;
        policySecretIn.cpHashA.b.size = 0;
        policySecretIn.policyRef.b.size = 0;
        policySecretIn.expiration = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&policySecretOut,
            (COMMAND_PARAMETERS *)&policySecretIn,
            NULL,
            TPM_CC_PolicySecret,
            TPM_RS_PW, authPw, 0,
            TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
        if (vverbose) 
            printf("makePolicySession: TPM2_PolicySecret: success\n");
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("ERROR: makePolicySession: TPM2_PolicySecret: failed, "
            "rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
        rc = EXIT_FAILURE;
    }
    return rc;
}

/* trustiphi_policySecret()
Run policy secret against the session.
@param[in] TSS context
@param[in] endorsement hierarchy handle
@param[in] policy session handle
@param[in] endorsement auth password
*/
static TPM_RC trustiphi_policySecret(TSS_CONTEXT *tssContext,
    TPMI_DH_ENTITY authHandle,
    TPMI_SH_AUTH_SESSION sessionHandle,
    const char* endorsementPw)
{
    TPM_RC			rc = 0;
    PolicySecret_In 		policySecretIn;
    PolicySecret_Out 		policySecretOut;

    if (rc == 0) {
        policySecretIn.authHandle = authHandle;
        policySecretIn.policySession = sessionHandle;
        policySecretIn.nonceTPM.b.size = 0;
        policySecretIn.cpHashA.b.size = 0;
        policySecretIn.policyRef.b.size = 0;
        policySecretIn.expiration = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&policySecretOut,
            (COMMAND_PARAMETERS *)&policySecretIn,
            NULL,
            TPM_CC_PolicySecret,
            TPM_RS_PW, endorsementPw, 0,
            TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/* Belows are functions from ibmacs976 ("server.c") */

/********************************************************************************/
/*										*/
/*			TPM 2.0 Attestation - Server 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: server.c 963 2017-03-15 20:37:25Z kgoldman $			*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* loadExternal() runs TPM2_LoadExternal, loading a key public part.

If name is not NULL, it is returned.

*/

static uint32_t loadExternal(TSS_CONTEXT *tssContext,
    TPM_HANDLE *objectHandle,
    TPM2B_NAME *name,
    TPMT_PUBLIC *inPublic)
{
    uint32_t 		rc = 0;
    LoadExternal_In 		loadExternalIn;
    LoadExternal_Out 		loadExternalOut;

    if (vverbose) printf("loadExternal: Entry\n");
    /* load the attestation key */
    if (rc == 0) {
        loadExternalIn.hierarchy = TPM_RH_NULL;
        loadExternalIn.inPrivate.t.size = 0;			/* only public key */
        loadExternalIn.inPublic.publicArea = *inPublic;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&loadExternalOut,
            (COMMAND_PARAMETERS *)&loadExternalIn,
            NULL,
            TPM_CC_LoadExternal,
            TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
        *objectHandle = loadExternalOut.objectHandle;
        if (name != NULL) {
            *name = loadExternalOut.name;	    /* copies the structure contents */
        }
        if (vverbose) printf("loadExternal: TPM2_LoadExternal handle %08x\n",
            loadExternalOut.objectHandle);
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("ERROR:loadExternal: TPM2_Load failed, rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}


/* makecredential() runs TPM2_MakeCredential

*/

static uint32_t makecredential(TSS_CONTEXT *tssContext,
    TPM2B_ID_OBJECT *credentialBlob,
    TPM2B_ENCRYPTED_SECRET *secret,
    TPM_HANDLE handle,
    TPM2B_DIGEST *credential,
    TPM2B_NAME *objectName)
{
    TPM_RC			rc = 0;
    MakeCredential_In 		makeCredentialIn;
    MakeCredential_Out 		makeCredentialOut;

    if (vverbose) printf("makecredential: Entry, handle %08x\n", handle);
    if (rc == 0) {
        makeCredentialIn.handle = handle;
        makeCredentialIn.credential = *credential;
        makeCredentialIn.objectName = *objectName;
    }
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&makeCredentialOut,
            (COMMAND_PARAMETERS *)&makeCredentialIn,
            NULL,
            TPM_CC_MakeCredential,
            TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
        *credentialBlob = makeCredentialOut.credentialBlob;
        *secret = makeCredentialOut.secret;
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("ERROR: makecredential: failed, rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}

/* Belows are functions from ibmtss1045 ("signapp.c") */

/********************************************************************************/
/*										*/
/*			    Sign Application					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: signapp.c 980 2017-04-04 21:11:44Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* policyGetDigest() traces the session policy digest for debugging.  It should be the same as the
policy in the EK template.

*/

static TPM_RC policyGetDigest(TSS_CONTEXT *tssContext,
    TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    PolicyGetDigest_In 		policyGetDigestIn;
    PolicyGetDigest_Out 	policyGetDigestOut;

    if (rc == 0) {
        policyGetDigestIn.policySession = sessionHandle;
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&policyGetDigestOut,
            (COMMAND_PARAMETERS *)&policyGetDigestIn,
            NULL,
            TPM_CC_PolicyGetDigest,
            TPM_RH_NULL, NULL, 0);
    }
    if (verbose) TSS_PrintAll("policyGetDigest",
        policyGetDigestOut.policyDigest.t.buffer,
        policyGetDigestOut.policyDigest.t.size);
    return rc;
}

/* createKey() creates a signing key under the EK storage key parentHandle.

policySessionHandle is a previously satisfied policy session.  continue is SET.

A command decrypt session is used to transfer the signing key userAuth encrypted.  A response
encrypt session is used just as a demo.

*/

static TPM_RC createKey(TSS_CONTEXT *tssContext,
    TPM2B_PRIVATE *outPrivate,
    TPM2B_PUBLIC *outPublic,
    TPMI_SH_AUTH_SESSION policySessionHandle,
    TPM_HANDLE parentHandle,
    const char *keyPassword,
    int pwSession)
{
    TPM_RC	rc = 0;
    Create_In 	createIn;
    Create_Out 	createOut;
    int 	attributes;
    /* hard code the policy since this test is also used for the no file support case */
    const uint8_t policy[] = { 0x7e, 0xa1, 0x0d, 0xe0, 0x05, 0xfc, 0xb2, 0x1d,
        0x44, 0xf2, 0x4b, 0xc8, 0xf7, 0x4c, 0x28, 0xa8,
        0xb9, 0xed, 0xf1, 0x4b, 0x1c, 0x53, 0xea, 0x4c,
        0xcf, 0x3c, 0x5a, 0x4c, 0xe3, 0x8c, 0x75, 0x6e };
    if (rc == 0) {
        createIn.parentHandle = parentHandle;
        rc = TSS_TPM2B_StringCopy(&createIn.inSensitive.sensitive.userAuth.b,
            keyPassword, sizeof(TPMU_HA));
    }
    /* policy command code sign + policy authvalue or policy password */
    if (rc == 0) {
        memcpy(&createIn.inPublic.publicArea.authPolicy.b.buffer, policy, sizeof(policy));
        createIn.inPublic.publicArea.authPolicy.b.size = sizeof(policy);
    }
    if (rc == 0) {
        createIn.inSensitive.sensitive.data.t.size = 0;
        createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
        createIn.inPublic.publicArea.type = TPM_ALG_RSA;	/* for the RSA template */
        createIn.inPublic.publicArea.objectAttributes.val = 0;
        createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
        createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
        createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
        createIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
        createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
        createIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
        createIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
        createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        createIn.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        createIn.inPublic.publicArea.unique.rsa.t.size = 0;
        createIn.outsideInfo.t.size = 0;
        createIn.creationPCR.count = 0;
        if (pwSession) {
            attributes = TPMA_SESSION_CONTINUESESSION;
        }
        else {
            attributes = TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION;
        }
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&createOut,
            (COMMAND_PARAMETERS *)&createIn,
            NULL,
            TPM_CC_Create,
            policySessionHandle, NULL, attributes,
            TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
        *outPrivate = createOut.outPrivate;
        *outPublic = createOut.outPublic;
    }
    return rc;
}

/* startSession() starts either a policy or HMAC session.

If tpmKey is not null, a salted session is used.

If bind is not null, a bind session is used.
*/

static TPM_RC startSession(TSS_CONTEXT *tssContext,
    TPMI_SH_AUTH_SESSION *sessionHandle,
    TPM_SE sessionType,			/* policy or HMAC */
    TPMI_DH_OBJECT tpmKey,		/* salt key, can be null */
    TPMI_DH_ENTITY bind,			/* bind object, can be null */
    const char *bindPassword)		/* bind object password, can be null */
{
    TPM_RC			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;

    /*	Start an authorization session */
    if (rc == 0) {
        startAuthSessionIn.tpmKey = tpmKey;			/* salt key */
        startAuthSessionIn.bind = bind;				/* bind object */
        startAuthSessionExtra.bindPassword = bindPassword;	/* bind object password */
        startAuthSessionIn.sessionType = sessionType;		/* HMAC or policy session */
        startAuthSessionIn.authHash = TPM_ALG_SHA256;		/* HMAC algorithm */
        startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;	/* parameter encryption */
        startAuthSessionIn.symmetric.keyBits.aes = 128;
        startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
        rc = TSS_Execute(tssContext,
            (RESPONSE_PARAMETERS *)&startAuthSessionOut,
            (COMMAND_PARAMETERS *)&startAuthSessionIn,
            (EXTRA_PARAMETERS *)&startAuthSessionExtra,
            TPM_CC_StartAuthSession,
            TPM_RH_NULL, NULL, 0);
        *sessionHandle = startAuthSessionOut.sessionHandle;
    }
    return rc;
}
