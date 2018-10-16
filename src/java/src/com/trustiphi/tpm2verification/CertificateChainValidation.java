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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import sun.security.provider.certpath.OCSP;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.DistributionPoint;
import sun.security.x509.GeneralNames;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;

public class CertificateChainValidation {
    
    private X509Certificate root = null;
    // first element in the chain is the target
    private List<X509Certificate> chain = new ArrayList<X509Certificate>();
    private Collection<X509CRL> crls = new ArrayList<X509CRL>();
    
    /**
     * Create an empty object
     */
    public CertificateChainValidation() {}
    
    /**
     * Create an object with the input values for the required elements
     * @param targetFilename The filename of platform certificate
     * @param cetFilemanes The filenames of CA certificates
     * @param crlUris The the URIs of CRL files
     */
    public CertificateChainValidation(String targetFilename, String[] certFilenames, String[] crlUris) {
        CertificateFactory certificateFactory = null;
        
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            System.out.println("ERROR: " + e.getLocalizedMessage());
        }
        
        if (certificateFactory != null) {
            // parse cert file to X509Certificate
            // target cert file
            X509Certificate targetCert = null;
            try {
                targetCert = (X509Certificate) certificateFactory
                        .generateCertificate(new FileInputStream(targetFilename));
                
            } catch (FileNotFoundException | CertificateException e) {
                System.out.println("ERROR: Can't parse " + targetFilename);
                System.out.println(e.getLocalizedMessage());
            }
            // the first element of chain must be the target
            chain.add(targetCert);
            
            if (targetCert == null) {
                // no need for further parsing
                return;
            }
            
            // CA cert file
            if (certFilenames == null || certFilenames.length == 0) {
                // input is only the platform cert
                // get certs in full CA chain
                X509Certificate cert = targetCert;
                
                while (root == null && cert != null) {
                    X509Certificate cacert = getIssuerCert(cert);           
                    if (cacert != null) {
                        if (isRoot(cacert)) {
                            root = cacert;
                        } else {
                            chain.add(cacert);
                        }
                    }
                    cert = cacert;
                }
            } else {
                // input is full CA chain
                for (String certFilename : certFilenames) {
                    X509Certificate cert = null;
                    try {
                        cert = (X509Certificate) certificateFactory
                                .generateCertificate(new FileInputStream(certFilename));
                    } catch (CertificateException | FileNotFoundException e) {
                        System.out.println("ERROR: Can't parse " + certFilename);
                        System.out.println(e.getLocalizedMessage());
                    }
                    if (cert != null) {
                        if (isRoot(cert)) {
                            root = cert;
                        } else {
                            chain.add(cert);
                        }
                    }
                }
            }

            // parse CRL URI to X509CRL
            if (crlUris == null || crlUris.length == 0) {
                // input has no CRL URIs
                // extract CRL from cert
                for (X509Certificate cert : chain) {
                    crls.addAll(getCrl(cert));
                }
            } else {
                // input has CRL URIs
                for (String crlUri : crlUris) {
                    X509CRL x509CRL = null;
                    try {
                        InputStream inputStream = new URL(crlUri).openConnection().getInputStream();
                        x509CRL = (X509CRL) certificateFactory.generateCRL(inputStream);                        
                        inputStream.close();
                    } catch (IOException | CRLException e) {
                        System.out.println("ERROR: Can't parse CRL from " + crlUri);
                        System.out.println(e.getLocalizedMessage());
                    }
                    if (x509CRL != null) {
                        crls.add(x509CRL);
                    }
                }
            }
        }
    }
    
    /**
     * Tell whether the root certificate is the root certificate
     * @param cert The X509 CA certificate
     * @return boolean This is true if the CA certificate is the root
     */
    public static boolean isRoot(X509Certificate cert) {        
//      String issuer = cert.getIssuerDN().getName();
//      String subject = cert.getSubjectDN().getName();
//      if (issuer.equals(subject)) {
//          return true;
//      } else {
//          return false;
//      }
        
        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException | CertificateException 
                | NoSuchAlgorithmException | NoSuchProviderException e) {
            return false;
        }       
    }
    
    /**
     * get CRL(s) (X509CRL) from certificate (X509Certificate) 
     * @param cert X509Certificate
     * @return Collection<X509CRL>
     */
    public static Collection<X509CRL> getCrl(X509Certificate cert) {
        Collection<X509CRL> retCrls = new ArrayList<X509CRL>();
        List<String> crlurls = getCrlUri(cert);
        for (String uri : crlurls) {
            X509CRL x509CRL = null;
            try {
                InputStream inputStream = new URL(uri.toString()).openConnection().getInputStream();
                x509CRL = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(inputStream);                                
                inputStream.close();
            } catch (IOException | CRLException | CertificateException e) {
                System.out.println("ERROR: Can't generate X509CRL from: " + uri);
                System.out.println(e.getLocalizedMessage());
            }
            if (x509CRL != null) {
                retCrls.add(x509CRL);
            }
        }
        return retCrls;
    }
    
    /**
     * Build certificate chain with CRL revocation
     * @return PKIXCertPathBuilderResult If it is not null, then success
     */
    public PKIXCertPathBuilderResult validateCrl() {
        return buildCertChain(true);
    }
    
    /**
     * Build certificate chain
     * @param flag True if CRL is checked when building the chain
     * @return PKIXCertPathBuilderResult If it is not null, then success
     */
    public PKIXCertPathBuilderResult buildCertChain(boolean flag) {
        PKIXCertPathBuilderResult builderResult = null;        
        try {
            /* Construct a valid path. */
            KeyStore anchors = KeyStore.getInstance(KeyStore.getDefaultType());
            anchors.load(null);
            anchors.setCertificateEntry("root", root);
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(chain.get(0));
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
            CertStoreParameters intermediates = new CollectionCertStoreParameters(chain);
            params.addCertStore(CertStore.getInstance("Collection", intermediates));
            if (flag) {
                CertStoreParameters revoked = new CollectionCertStoreParameters(crls);
                params.addCertStore(CertStore.getInstance("Collection", revoked));
            } else {
                params.setRevocationEnabled(false);
            }
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            /*
             * If build() returns successfully, the certificate is valid. More details about
             * the valid path can be obtained through the PKIXBuilderResult. If no valid
             * path can be found, a CertPathBuilderException is thrown.
             */
            builderResult = (PKIXCertPathBuilderResult) builder.build(params);
        } catch (Exception e) {
            //e.printStackTrace();
        }
        return builderResult;
    }
    
    /**
     * Validate certificate based on OCSP
     * @param userCert The certificate to be checked
     * @param cacert The issuer certificate
     * @param uri The URI of OCSP responder
     * @return boolean This is true if OCSP is validated
     */
    public static boolean validateOcsp(X509Certificate userCert, X509Certificate caCert, URI uri) {
        OCSP.RevocationStatus ocsp = null;
        try {
            ocsp = OCSP.check(userCert, caCert, uri, caCert, new Date());
            if (ocsp.getCertStatus().ordinal() == 0) {
                return true;
            } else {
                return false;
            }
        } catch (CertPathValidatorException | IOException e) {
            e.printStackTrace();
            return false;
        }        
    }
    
    /**
     * Validate certificate chains based on OCSP
     * @param builderResult The PKIXCertPathBuilderResult (CA chain)
     * @return boolean This is true if OCSP in the full chain is validated
     */
    public static boolean validateOcsp(PKIXCertPathBuilderResult builderResult) {
        if (builderResult == null 
                || builderResult.getCertPath() == null  
                || builderResult.getCertPath().getCertificates() == null) {
            return false;
        }
        List<? extends Certificate> certs = builderResult.getCertPath().getCertificates();
        Iterator<? extends Certificate> it = certs.iterator();
        X509Certificate userCert = null;
        X509Certificate caCert = null;
        
        if (it.hasNext()) {
            userCert = (X509Certificate) it.next();
        }
        while (it.hasNext()) {         
            caCert = (X509Certificate) it.next();         
            URI uri = OCSP.getResponderURI(userCert);             
            if (uri != null) {
                boolean flag = validateOcsp(userCert, caCert, uri);
                if (!flag) {
                    return false;
                }
            }
            userCert = caCert;
        }
        // root cert
        caCert = builderResult.getTrustAnchor().getTrustedCert();
        if (userCert != null && caCert != null) {
            URI uri = OCSP.getResponderURI(userCert);             
            if (uri != null) {
                boolean flag = validateOcsp(userCert, caCert, uri);
                if (!flag) {
                    return false;
                }
            }
        }
        return true;        
    }
    
    /**
     * Walk through certificate chain and validate certificate based on OCSP first then CRL 
     * @param builderResult The PKIXCertPathBuilderResult (CA chain)
     * @return boolean This is true if the full chain is not revoked
     */
    public static boolean validateOcspCrl(PKIXCertPathBuilderResult builderResult) {
        if (builderResult == null 
                || builderResult.getCertPath() == null  
                || builderResult.getCertPath().getCertificates() == null) {
            return false;
        }
        List<? extends Certificate> certs = builderResult.getCertPath().getCertificates();
        Iterator<? extends Certificate> it = certs.iterator();
        X509Certificate userCert = null;
        X509Certificate caCert = null;
        
        if (it.hasNext()) {
            userCert = (X509Certificate) it.next();
        }
        while (it.hasNext()) {         
            caCert = (X509Certificate) it.next();         
            if (!validateOcspCrl(userCert, caCert)) {
                return false;
            }
            userCert = caCert;
        }
        // root cert
        caCert = builderResult.getTrustAnchor().getTrustedCert();
        if (userCert != null && caCert != null) {
            if (!validateOcspCrl(userCert, caCert)) {
                return false;
            }
        }
        return true;        
    }
    
    /**
     * Validate certificate based on OCSP first then CRL 
     * @param userCert User certificate in X509 format
     * @param caCert CA certificate in X509 format
     * @return boolean This is true if certificate is not revoked
     */
    public static boolean validateOcspCrl(X509Certificate userCert, X509Certificate caCert) {
        URI uri = OCSP.getResponderURI(userCert);
        if (uri != null) {
            // OCSP exists; check OCSP
            return validateOcsp(userCert, caCert, uri);
        } else {
            // OCSP doesn't exist; check CRL
            Collection<X509CRL> retCrls = getCrl(userCert);
            for (X509CRL x509CRL : retCrls) {
                // cert is revoked
                if (!validateCrl(userCert, caCert, x509CRL)) {
                    return false;
                }
            }
            return true;
        }
    }
    
    /**
     * Get CRL URL(s) from certificate 
     * @param cert Certificate in X509 format
     * @return A list of CRL URL(s)
     */
    public static List<String> getCrlUri(X509Certificate cert) {
        List<String> crlurls = new ArrayList<String>();        
        CRLDistributionPointsExtension crlDistroExten = null;
        
        try {
            X509CertImpl x509Cert = new X509CertImpl(cert.getEncoded());
            crlDistroExten = x509Cert.getCRLDistributionPointsExtension();
        } catch (CertificateException e) {
            System.out.println("ERROR: Can't get CRL extension from cert");
            System.out.println(e.getLocalizedMessage());
        }
        
        if (crlDistroExten != null) {
            ArrayList<DistributionPoint> distros = null;
            try {
                distros = (ArrayList<DistributionPoint>) crlDistroExten
                        .get(CRLDistributionPointsExtension.POINTS);
            } catch (IOException e) {
                System.out.println("ERROR " + e.getLocalizedMessage());
            }
            if (distros != null) {
                for (DistributionPoint distributionPoint : distros) {
                    GeneralNames distroName = distributionPoint.getFullName();
                    for (int i = 0; i < distroName.size(); ++i) {
                        URI uri = ((URIName) distroName.get(i).getName()).getURI();
                        if (uri != null) {
                            crlurls.add(uri.toString());
                        }
                    }
                }
            }
        }
        return crlurls;
    }
    
    /**
     * Validate certificate based on CRL 
     * @param cert Certificate in X509 format
     * @param crlurl URL for CRL
     * @return boolean This is true if certificate is not revoked
     */
    public static boolean validateCrlUri(X509Certificate cert, String crlurl) {
        X509CRL x509CRL = null;
        try {
            InputStream inputStream = new URL(crlurl).openConnection().getInputStream();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x509CRL = (X509CRL) certificateFactory.generateCRL(inputStream);                        
            inputStream.close();
        } catch (IOException | CRLException | CertificateException e) {
            System.out.println("ERROR: Can't load CRL from " + crlurl);
            return false;
        }
        if (x509CRL != null) {
            X509Certificate issuerCert = getIssuerCert(cert);
            if (issuerCert != null && validateCrl(cert, issuerCert, x509CRL)) {
                return true;
            }            
        }
        return false;
    }
    
    /**
     * Validate certificate based on CRL 
     * @param cert Certificate in X509 format
     * @param crlFilename CRL file
     * @return boolean This is true if certificate is not revoked
     */
    public static boolean validateCrlFile(X509Certificate cert, String crlFilename) {
        X509CRL x509CRL = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x509CRL = (X509CRL) certificateFactory.generateCRL(new FileInputStream(crlFilename));                        
        } catch (IOException | CRLException | CertificateException e) {
            System.out.println("ERROR: Can't load CRL from " + crlFilename);
            return false;
        }
        if (x509CRL != null) {
            X509Certificate issuerCert = getIssuerCert(cert);
            if (issuerCert != null && validateCrl(cert, issuerCert, x509CRL)) {
                return true;
            }            
        }
        return false;
    }
    
    /**
     * Verify CRL is signed by issuer certificate
     * Validate certificate is not revoked based on CRL 
     * @param userCert Certificate in X509 format
     * @param issuerCert Certificate in X509 format
     * @param x509CRL X509CRL
     * @return boolean This is true if CRL is verified and user certificate is not revoked
     */
    public static boolean validateCrl(X509Certificate userCert, X509Certificate issuerCert, X509CRL x509CRL) {
        PublicKey publicKey = issuerCert.getPublicKey();
        if (publicKey != null) {
            // check CRL's signature using issuer's public key
            try {
                x509CRL.verify(publicKey);
            } catch (InvalidKeyException | CRLException | NoSuchAlgorithmException | NoSuchProviderException
                    | SignatureException e) {
                System.out.println("ERROR: CRL is not verified by issuer's public key");
                return false;
            }
            // check CRL is revoked
            if (x509CRL.getRevokedCertificate(userCert.getSerialNumber()) == null) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get issuer certificate of user certificate
     * @param userCert Certificate in X509 format
     * @return Issuer certificate in X509 format 
     */
    public static X509Certificate getIssuerCert(X509Certificate userCert) {
        X509Certificate issuerCert = null;
        String issuerUri = null;
        // get issuer URI
        try {
             AuthorityInfoAccessExtension extension = new X509CertImpl(userCert.getEncoded())
                     .getAuthorityInfoAccessExtension();
             if (extension != null) {
                 issuerUri = extension.getAccessDescriptions().get(0).getAccessLocation().toString();
             } else {
                 System.out.println("ERROR: Can't get AuthorityInfoAccessExtension of cert");
                 try {
                    System.out.println(new X509CertImpl(userCert.getEncoded()).
                            getUnparseableExtension(new ObjectIdentifier("1.3.6.1.5.5.7.1.1")));
                } catch (IOException e) {
                    System.out.println(userCert);
                }
             }
        } catch (CertificateException e) {
            System.out.println("ERROR: Can't get issuer URI of cert");
            System.out.println(e.getLocalizedMessage());
        }
        if (issuerUri != null) {
            issuerUri = issuerUri.substring(issuerUri.indexOf(':') + 1);
            
            // get cert based on issuer URIs
            try {
                issuerCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new URL(issuerUri).openConnection().getInputStream());
            } catch (CertificateException | IOException e) {
                System.out.println("ERROR: Can't parse cert from " + issuerUri);
                System.out.println(e.getLocalizedMessage());
            }
        }
        return issuerCert;
    }
}
