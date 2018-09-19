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

package com.trustiphi.tpm2verification;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

public class VerifyEKCert {
    
    /**
     * Verify Ek cert against the CA certs
     * @param args[0] A list including filenames of CA certs
     * @param args[1] Filename of EK cert
     */
    public static void main(String[] args) {
        boolean verbose = false;
        
        if (args.length < 2) {
            printUsage();
        }
        if (args.length > 2 && args[2].equals("-v")) {
            verbose = true;
        }
        
        // list name of CA certificates
        String ekccaList = args[0];
        // EK cert
        String ekc = args[1];
        // list of CA filenames
        ArrayList<String> ekcca = new ArrayList<String>();
        
        readList(ekccaList, ekcca);
        
        if (ekcca.size() > 1) {
            // more than one CA cert
            PKIXCertPathBuilderResult builderResult = new CertificateChainValidation(ekc, 
                    ekcca.toArray(new String[ekcca.size()]), null).validateCrl();
            if (builderResult != null) {
                System.out.println("INFO: Successfully verified EK cert");
                if (verbose) {
                    System.out.println(builderResult);
                }
                return;
            } else {
                System.out.println("ERROR: Failed to verify EK cert");
                System.exit(1);
            }
        } else if (ekcca.size() == 1) {
            // only one CA cert            
            X509Certificate cacert = null;
            try {
                cacert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new FileInputStream(ekcca.get(0)));                
            } catch (FileNotFoundException | CertificateException e) {
                System.out.println("ERROR: Can't parse " + ekcca.get(0));
                System.out.println(e.getLocalizedMessage());
                System.exit(1);
            }
            // is root CA?
            if (!CertificateChainValidation.isRoot(cacert)) {
                System.out.println("ERROR: " + ekcca.get(0) + " is not root CA cert.");
                System.exit(1);
            } 
            X509Certificate ekcert = null;
            try {
                ekcert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new FileInputStream(ekc));                        
            } catch (FileNotFoundException | CertificateException e) {
                System.out.println("ERROR: Can't parse " + ekc);
                System.out.println(e.getLocalizedMessage());
                System.exit(1);
            }                
            // verify signature
            if (!verifyEKCertSignature(ekcert, cacert)) {
                System.out.println("ERROR: Failed to  verify signaure of EK cert");
                System.exit(1);
            }
            // verify CRL
            if (!verifyEKCertCRL(ekcert, cacert)) {
                System.out.println("ERROR: Failed to verify CRL of EK cert");
                System.exit(1);
            }
            System.out.println("INFO: Successfully verified EK cert");
        } else {
            System.out.println("ERROR: Failed to verify EK cert: CA cert list is empty");
            System.exit(1);
        }
    }
    
    /**
     * Read filenames from the list
     * @param ekccaList A list including filenames of CA certs
     * @param ekcca ArrayList that including the filenames of CA certs
     */
    public static void readList(String ekccaList, ArrayList<String> ekcca) {
        BufferedReader br;
        String line = null;
        
        try {
            br = new BufferedReader(new FileReader(new File(ekccaList)));
            while ((line = br.readLine()) != null) {
                ekcca.add(line);
            }
            br.close();
        } catch (FileNotFoundException e) {
            System.out.println("ERROR: Can't open file " + ekccaList);
            System.exit(1);
        } catch (IOException e) {
            System.out.println("ERROR: Can't process file " + ekccaList);
            System.exit(1);
        }
    }

    /**
     * Print usage
     */
    public static void printUsage() {
        final String usage = "\nVerifyEKCert <filename of CA cert list> <filename of EK cert> [<-v>]\n"
                + "-v     Verbose mode";
        System.out.println(usage);
        System.exit(1);
    }
    
    /**
     * Verify CA's signature in EK cert
     * @param ekcert EK X509Certificate
     * @param cacert CA X509Certificate
     * @return True if EK cert is verified
     */
    public static boolean verifyEKCertSignature(X509Certificate ekcert, X509Certificate cacert) {
        if (ekcert == null || cacert == null) {
            return false;
        }
        PublicKey key = cacert.getPublicKey();
        if (key != null) {
            try {            
                ekcert.verify(key);
                return true;
            } catch (SignatureException | InvalidKeyException | CertificateException 
                    | NoSuchAlgorithmException | NoSuchProviderException e) {
                return false;
            }
        }
        return false;
    }
    
    /**
     * Verify CRL of EK cert
     * @param ekcert EK X509Certificate
     * @param cacert CA X509Certificate 
     * @return True if EK cert is verified
     */
    public static boolean verifyEKCertCRL(X509Certificate ekcert, X509Certificate cacert) {
        if (ekcert == null || cacert == null) {
            return false;
        }
        Collection<X509CRL> x509CRLs = CertificateChainValidation.getCrl(ekcert);
        for (X509CRL x509CRL : x509CRLs) {
            // cert is revoked
            if (!CertificateChainValidation.validateCrl(ekcert, cacert, x509CRL)) {
                return false;
            }
        }  
        return true;        
    }
}
