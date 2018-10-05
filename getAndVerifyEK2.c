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

/* getAndVerifyEK2.c: read EK cert from TPM, validate EK cert, 
and compare EK in the cert with EK in the TPM 
*/

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

#include <openssl/pem.h>

#include "config.h"
#include "ekutils.h"
#include "cryptoutils.h"
#include "commonerror.h"
#include "commontss.h"
#include "objecttemplates.h"

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

static TPM_RC createEkPrimary(TSS_CONTEXT *tssContext,
    TPMI_RH_NV_INDEX ekCertIndex,
    const char* endorsementPw,
    TPM_HANDLE *ekKeyHandle,
    TPMT_PUBLIC *tpmtPublicOut);

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

static void printUsage();

int vverbose =0;
int verbose = 0;

int main(int argc, char* argv[])
{
    TPM_RC rc = 0;
    int	i; /* argc iterator */
    TSS_CONTEXT  *tssContext = NULL;
    /* EK cert index */
    TPMI_RH_NV_INDEX ekCertIndex = EK_CERT_RSA_INDEX;   /* default rsa */
    /* CA cert filename*/
    const char *ekcacert = NULL;
    /* EK cert filename */
    const char* ekc = NULL;
    /* output EK cert PEM file */
    const char* ekout = NULL;
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
        rc = validateEkCert(tssContext, &ekCertIndex, ekcacert, ekc,
            endorsementPw, ekout, &ekKeyHandle, &ekPub);
    }
    /* flush EK */
    if (ekKeyHandle != 0) {
        if (verbose) printf("INFO: Flush EK %08x\n",
            ekKeyHandle);
        TPM_RC rc1 = flushContext(tssContext, ekKeyHandle);
        if (rc == 0) {
            rc = rc1;
        }
    }
    /* delete TSS context*/
    {
        TPM_RC rc1 = TSS_Delete(tssContext);
        tssContext = NULL;
        if (rc == 0) {
            rc = rc1;
        }
    }

    return rc;
}

/* pinrtUsage()
*/
static void printUsage()
{
    printf("\n");
    printf("getAndVerifyEK2  -ekcacert <filename> [-ekc <filename>] "
        "[-ekout <filename>] [-ekindex <1 | 2>] [-endorsementpw <password>] "
        "[-v]\n");
    printf("\n");
    printf("-ekcacert <filename>  where the file contains a list of filenames of CA certificates\n");
    printf("                      (including the root and intermeidate ones) for the EK certificate\n");
    printf("-ekc <filename>       where the file contains the EK certificate\n");
    printf("-ekout <filename>     where filename is the name of the output EK Cert PEM file\n");
    printf("-ekindex <1 | 2>      The built-in EK certificate \"index\" indicating which EK certificate\n");
    printf("                      in the NV to use, RSA, or ECC. 1 for RSA and 2 for ECC.\n");
    printf("                      This is not a required option. If not included on the command line,\n");
    printf("                      the code will attempt to use RSA and if not found will use ECC.\n");
    printf("-endorsementpw        password for endorsement auth\n");
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
        //unsigned char *tmpCert = ekCertBin;
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

/* trustiphi_processCreatePrimary()
Combine the EK nonce and EK template from NV to form the createprimary input.
It creates the primary key.
ekCertIndex determines whether an RSA or ECC key is created.
If nonce is NULL, the default IWG templates are used.
If nonce is non-NULL, the nonce and tpmtPublicIn are used.
After returning the TPMT_PUBLIC, flushes the primary key unless noFlush is TRUE.
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
