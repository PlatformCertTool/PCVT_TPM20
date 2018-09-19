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

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;

import javax.xml.bind.JAXBException;

import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.trustiphi.asn1.EndorsementKeyCertificateHolder;

public class VerifyPlatformCert {

    /**
     * Verify platform cert against the CA certs
     * @param args[0] Filename of CA cert that signs the platform cert
     * @param args[1] Filename of platform cert or directory that includes platform cert
     * @param args[2] URL of CRL
     * @param args[3] Filename of the EK cert
     */
    public static void main(String[] args) {
        // program success flag
        boolean flag = true;
        boolean verbose = false;
        //platform cert
        String pc = null;
        // output XML filename
        String outputXML = null;        
        
            printUsage1();

        if (args.length < 5) {
            printUsage();
        }
        if (args.length > 4) {
            // optional parameters
            for (int i = 4; i < args.length; i++) {
                if (args[i].equals("-v")) {
                    verbose = true;
                } else {
                    outputXML = args[i];
                }
            }
        }
        
        // filename of CA cert that signs the platform cert
        String pcca = args[0];
        // CRL URL
        String crlurl = args[2];
        // filename of EK cert
        String ekc = args[3]; 
      
        // CA chain result
        PKIXCertPathBuilderResult builderResult = null;
        // CA chain verification success flag
        boolean success = false;        
        
        File certFile = new File(args[1]);
    	PlatformCertificateHolder platformCertificateHolder = null;
        
        if (certFile.isDirectory()) {
            // input is platform cert directory
            // try each file in the directory for verification
            for (File file : certFile.listFiles()) {                
                if (!file.isDirectory()) {
                    // verify platform cert against ca cert abd crl
					try {
						platformCertificateHolder = loadPlatformCertFromFile(file.getAbsolutePath(), verbose);
					} catch (IOException e) {
						continue;
					}
                	
                	if (verifyPcSignature(platformCertificateHolder, pcca))
                	{
                        pc = file.getAbsolutePath();                         
                        if (verbose) {
                        	System.out.println("INFO: Successfully verified platform certificate signature");
                        }
                        
                		if (verifyPcCrl(platformCertificateHolder, crlurl))
                		{
                            if(verbose) {
                            	System.out.println("INFO: Successfully verified platform cert against CRL");
                            }
                            
                            // verify the CA chain
                            AbstractMap.SimpleEntry<Boolean, PKIXCertPathBuilderResult> result = verifyPlatformCaChain(pcca);
                            success = result.getKey();
                            builderResult = result.getValue();
                            
                            if (success) {                                     
                                System.out.println("INFO: Found correct platform cert: " + pc);
                                break;
                            }
                            else {
                            	if(verbose) {
                            		System.out.println("INFO: Failed to validate platform cert chain on " + pc +"; Continuing to searcg for matching certificate...");                            	
                            	}
                            }
                		}
                		else {
                            System.out.println("WARN: Platform certificate CRL verification failed!");
                		}
                	}
                }
            }
        } else {
            // input is platform cert file
            pc = args[1];

			try {
				platformCertificateHolder = loadPlatformCertFromFile(pc, verbose);
        	
	        	if(verifyPcSignature(platformCertificateHolder, pcca))
	        	{
	        		if (verbose) {
	        		    System.out.println("INFO: Successfully verified platform certificate signature");
	        		}
	
	        		if (verifyPcCrl(platformCertificateHolder, crlurl))
	        		{
	                    if (verbose) {
	                    	System.out.println("INFO: Successfully verified platform cert against CRL");
	                    }
	                    
	                    // verify the CA chain
	                    AbstractMap.SimpleEntry<Boolean, PKIXCertPathBuilderResult> result = verifyPlatformCaChain(pcca);
	                    success = result.getKey();
	                    builderResult = result.getValue();
	        		}
	        		else {
                        System.out.println("WARN: Platform certificate CRL verification failed!");
	        		}
	        	}
	        	else {
	        		System.out.println("WARN: Signature verification on platform certificate failed.");
	        	}
			} catch (IOException e) {
        		System.out.println("ERROR: " + e.getLocalizedMessage());
        		System.out.println("ERROR: Failed to parse platform certificate file: " + pc);
			}
        }        
        
        if (success) {            
            if (verbose) {
                System.out.println("INFO: Successfully verified platform cert CA chain and CRLs");
                if (builderResult != null) {
                    // only when platform cert have >= 3 CA certs in the chain, builderResult is not null
                    System.out.println(builderResult);
                }
            }
            System.out.println("INFO: Successfully verified platform cert");
        } else {
            System.out.println("ERROR: Failed to verify platform cert");
            flag = false;
        }
        
        if (pc != null) {
            // compare the serial number of EK cert and platform cert holder
        	EndorsementKeyCertificateHolder ekCert=null;
			try {
				ekCert = EndorsementKeyCertificateHolder.loadInstance(ekc);
			} catch (IOException e) {
                System.out.println("ERROR: Failed to parse EK Cert file " + ekc + ": " + e.getLocalizedMessage());
                flag = false;
			}			
        	
            if (ekCert != null && platformCertificateHolder != null &&  compareEkcAndPc(ekCert, platformCertificateHolder)) {
                System.out.println("INFO: EK cert and platform cert are matched");
            } else {
                System.out.println("ERROR: EK cert and platform cert are not matched");
                flag = false;
            }
      
	        if (platformCertificateHolder != null &&  outputXML != null) {
	            // output platform cert to XML format
	            try {
					PlatformCertificateManager.writeToXML(platformCertificateHolder, new FileOutputStream(new File(outputXML)));
	                System.out.println("INFO: Wrote platform certificate file " + pc + " to XML file " + outputXML);
				} catch (FileNotFoundException e) {
	                System.out.println("ERROR: Failed to open output file: " + e.getLocalizedMessage());
				} 
	            catch (JAXBException e) {
	                System.out.println("ERROR: Failed to write output file: " + e.getLocalizedMessage());
				}
	        }    
        }
        
        if (!flag) {
            System.exit(1);
        }

    }
    
    /**
     * Print usage
     */
    public static void printUsage() {
        final String usage = "\nVerifyPlatformCert <filename of CA cert list> <filename/directory of platform cert> "
                + "<filename of CRL URLs> <filename of EK cert> [<-v>] [<filename of output XML>]\n"
                + "-v     Verbose mode";
        System.out.println(usage);
        System.exit(1);
    }
    
    public static void printUsage1() {
        final String usage = "\nVerifyPlatformCert <filename of CA cert list> <filename/directory of platform cert> "
                + "<filename of CRL URLs> <filename of EK cert> [<-v>] [<filename of output XML>]\n"
                + "-v     Verbose mode";
        System.out.println(usage);
        System.exit(1);
    }

    /**
     * Verify platform cert against CA cert
     * @param platformCertificateHolder platform cert
     * @param pcca Filename of CA cert that signs plarform cert
     * @return This is true if verification is successful
     */
    public static boolean verifyPcSignature(PlatformCertificateHolder platformCertificateHolder, String pcca) {
        // verify CA signature of platform cert

        // get public key from CA cert
        PublicKey publicKey = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certificateFactory
                    .generateCertificate(new FileInputStream(pcca));
            publicKey = cert.getPublicKey();
        } catch (IOException | CertificateException e) {
            System.out.println("ERROR: Failed to load Public Key from file " + pcca);
            return false;
        }
        
        // verify signature
        boolean signatureVerified = false;
        if (publicKey != null) {
            try {
                signatureVerified = platformCertificateHolder.verifySignature(publicKey);
                return signatureVerified;
                
            } catch (InvalidKeyException | OperatorCreationException | NoSuchAlgorithmException 
                    | SignatureException | IOException | javax.security.cert.CertificateException e) {
                System.out.println("ERROR: Signature of platform cert is not verified");
                return false;
            }
        }
      
        return false;
    }
    
    /**
     * Verify platform cert against CRL
     * @param platformCertificateHolder platform cert
     * @param CRL URL
     * @return This is true if verification is successful
     */
    public static boolean verifyPcCrl(PlatformCertificateHolder platformCertificateHolder, String crlurl) {
        // verify CRL
        X509CRL x509CRL = null;
        try {
        	URLConnection url = new URL(crlurl).openConnection();
        	url.setConnectTimeout(5000);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x509CRL = (X509CRL) certificateFactory.generateCRL(url.getInputStream());                        
        } 
        catch (IOException | CRLException | CertificateException e) {
            System.out.println("ERROR: " + e.getLocalizedMessage());
            System.out.println("ERROR: Can't load CRL from " + crlurl);
            return false;
        }
        if (x509CRL != null && x509CRL.getRevokedCertificate(
                platformCertificateHolder.getX509AttributeCertificateHolder().getSerialNumber()) == null) {
            return true;
        }         
        
        return false;
    }    
 
    /**
     * @param platformCertificateHolder PlatformCertificateHolder
     * @param caCert X509Certificate
     * @param crlurl URL of CRL
     * @param ocspurl URL of OCSP responder
     * @return True if platform certificate is verified
     */
    public static boolean verfiyPc(PlatformCertificateHolder platformCertificateHolder, 
            X509Certificate caCert, String crlurl, String ocspurl) {
        // verify signature
        PublicKey publicKey = null;
        boolean signatureVerified = false;        
        try {
            publicKey = caCert.getPublicKey();
            signatureVerified = platformCertificateHolder.verifySignature(publicKey);
        } catch (InvalidKeyException | OperatorCreationException | NoSuchAlgorithmException 
                | SignatureException | IOException | javax.security.cert.CertificateException e) {
            System.out.println("ERROR: Signature of platform cert is not verified");
            return false;
        }
       
        if (signatureVerified) {            
            if (ocspurl != null) {
                // verify OCSP if OCSP exits           
                OCSPResp ocspResponse = null;
                    
                try {
                    CertificateID id = new CertificateID(
                            new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                            new JcaX509CertificateHolder(caCert), platformCertificateHolder
                            .getX509AttributeCertificateHolder().getSerialNumber());
                    
                    OCSPReqBuilder gen = new OCSPReqBuilder();
                    
                    gen.addRequest(id);
                    
                    OCSPReq request =  gen.build();
                    
                    byte[] array = request.getEncoded();
                    URL urlt = new URL(crlurl);
                    HttpURLConnection con = (HttpURLConnection)urlt.openConnection();
                    con.setRequestProperty("Content-Type", "application/ocsp-request");
                    con.setRequestProperty("Accept", "application/ocsp-response");
                    con.setDoOutput(true);
                    OutputStream out = con.getOutputStream();
                    DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                    dataOut.write(array);
                    dataOut.flush();
                    dataOut.close();
                    if (con.getResponseCode() / 100 != 2) {
                        throw new IOException("Invalid HTTP response");
                    }
                    //Get Response
                    InputStream in = (InputStream) con.getContent();
                    ocspResponse = new OCSPResp(in);                    
                    
                } catch (CertificateEncodingException | OperatorCreationException | OCSPException | IOException e) {
                    System.out.println("ERROR: Can't get OCSP response from " + ocspurl);
                    return false;
                }
                if (ocspResponse != null) {
                    if(ocspResponse.getStatus() == 0) {
                        return true;
                    } else {
                        System.out.println("ERROR: Platform cert is revoked");
                    }                    
                }
            } else {
                // verify CRL if OCSP doesn't exist
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
                    // check CRL's signature using issuer's public key
                    try {
                        x509CRL.verify(publicKey);
                    } catch (InvalidKeyException | CRLException | NoSuchAlgorithmException | NoSuchProviderException
                            | SignatureException e) {
                        System.out.println("ERROR: CRL is not verified by issuer's public key: " + crlurl);
                        return false;
                    }
                    // check CRL is revoked
                    if (x509CRL.getRevokedCertificate(
                            platformCertificateHolder.getX509AttributeCertificateHolder().getSerialNumber()) == null) {
                        return true;
                    } else {
                        System.out.println("ERROR: Platform cert is revoked");
                    }
                }
            }
        }
        
        return false;
    } 
    
    /**
     * Compare the serial number of EK cert and the platform cert hodler
     * @param ekc EK certificate
     * @param platform cert
     * @return boolean This is true if EK cert and platform cert match
     */
    public static boolean compareEkcAndPc(EndorsementKeyCertificateHolder ekc, PlatformCertificateHolder pc) {
        if (ekc.getSerialNumber().equals(pc.getX509AttributeCertificateHolder().getHolder().getSerialNumber())) {
            return true;
        } else {
            return false;
        }
    }

     /**
     * Load the Platform Cert from file
     * @param pc Filename of platform cert
     * @return the loaded PlatformCertificateHolder
     * @throws IOException 
     */
    public static PlatformCertificateHolder loadPlatformCertFromFile(String pc, boolean verbose) throws IOException {
        PlatformCertificateHolder platformCert = new PlatformCertificateHolder();
        try {
            // try pem format for pc
            platformCert.loadFromFilePEM(new File(pc));
            if(verbose)
            {
            	System.out.println("INFO: Loaded Platform Certificate PEM file " + pc);
            }
        } catch (IOException e) {
            // try der format for pc
            platformCert.loadFromFileDER(new File(pc));
            if(verbose)
            {
            	System.out.println("INFO: Loaded Platform Certificate DER file " + pc);
            }
        }
        
        return platformCert;
    }    
    
    /**
    * Verify platform cert CA chain
    * @param pcca Filename of platform cert CA cert
    * @return flag of verification success and CA chain builder result
    */
    public static AbstractMap.SimpleEntry<Boolean, PKIXCertPathBuilderResult> verifyPlatformCaChain(String pcca) {
        boolean success = false;
        PKIXCertPathBuilderResult builderResult = null;
        
        X509Certificate cacert = null;
        try {
            cacert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new FileInputStream(pcca));
        } catch (FileNotFoundException | CertificateException e) {
            System.out.println("ERROR: Can't parse " + pcca);
            System.out.println(e.getLocalizedMessage());
        }
        
        if (cacert != null) {                                
            if (CertificateChainValidation.isRoot(cacert)) {
                // platform cert CA is root CA
                success = true;
            }
            else {
                // issuer of platform cert CA cert
                X509Certificate cacert1 = CertificateChainValidation.getIssuerCert(cacert);
                if (cacert1 != null) {
                    if (CertificateChainValidation.isRoot(cacert1)) {
                        // platform cert CA cert's issuer is root CA                                        
                        // verify signature and CRL
                        if (!VerifyEKCert.verifyEKCertSignature(cacert, cacert1)) {
                            System.out.println("ERROR: Failed to verify signaure of platform CA cert");
                        } 
                        else if (!VerifyEKCert.verifyEKCertCRL(cacert, cacert1)) {
                            System.out.println("ERROR: Failed to verify CRL of platform CA cert");
                        }
                        else {
                            success = true;
                        }
                    }
                    else {
                        builderResult = new CertificateChainValidation(pcca, null, null).validateCrl();
                        if (builderResult != null) {
                            success = true;
                        }
                    }
                }                         
            }
        }        
        return new AbstractMap.SimpleEntry<Boolean, PKIXCertPathBuilderResult>(success, builderResult);
    }
    
}
