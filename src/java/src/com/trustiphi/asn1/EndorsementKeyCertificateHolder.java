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
*/

/**
 * @author admin
 *
 */
package com.trustiphi.asn1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import com.trustiphi.tpm2verification.PlatformCertificateHolder;
import com.trustiphi.tpm2verification.TP_FileUtils;

public class EndorsementKeyCertificateHolder extends X509CertificateHolder {

	/**
	 * @param certificateBytes the X509Certificate representing the EK
	 * @throws IOException
	 */
	public EndorsementKeyCertificateHolder(byte[] certificateBytes) throws IOException {
		super(certificateBytes);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param certificate the X509Certificate representing the EK
	 */
	public EndorsementKeyCertificateHolder(Certificate certificate) {
		super(certificate);
		// TODO Auto-generated constructor stub
	}

	public static EndorsementKeyCertificateHolder loadInstance(String filename) throws IOException
	{
		X509CertificateHolder cert = parseX509CertificateFromFile(filename);
		return new EndorsementKeyCertificateHolder(cert.getEncoded());
	}
	
	public PlatformCertificateHolder toPlatformCertificateHolder() {
		PlatformCertificateHolder platformCert = new PlatformCertificateHolder();
		AttributeCertificateHolder attr_cert_holder = new AttributeCertificateHolder(this.getSubject(), this.getSerialNumber());
		platformCert.setHolder(attr_cert_holder);
		
		return platformCert;
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// load pem file 
		Security.addProvider(new BouncyCastleProvider());
		
		if(args.length < 2)
		{
			System.out.println("Missing argument!");
			System.exit(-1);
		}

		String ek_cert_filename = args[0];
		String ca_cert_filename = args[1];
		
///////////////
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			java.security.cert.X509Certificate ekcert = (X509Certificate) cf.generateCertificate(new FileInputStream(ek_cert_filename));
			java.security.cert.X509Certificate cacert = (X509Certificate) cf.generateCertificate(new FileInputStream(ca_cert_filename));
			
			ekcert.verify(cacert.getPublicKey());
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
///////////////
		
		
		
		try {

			//---------
			// Get the EK Certificate
			//---------
			X509CertificateHolder certFileHolder = parseX509CertificateFromFile(ek_cert_filename);
			
			EndorsementKeyCertificateHolder ek = new EndorsementKeyCertificateHolder(((X509CertificateHolder)certFileHolder).toASN1Structure());
			System.out.println("Issuer: " + ek.getIssuer());
			System.out.println("SN: " + ek.getSerialNumber());
			System.out.println("EK Public Key: " + ek.getSubjectPublicKeyInfo().getPublicKeyData());
            System.out.println("EK: Public Key Pad Bytes: " + ek.getSubjectPublicKeyInfo().getPublicKeyData().getPadBits());
			System.out.println("Subject: " + ek.getSubject());
//			IssuerAndSerialNumber iandsn = IssuerAndSerialNumber.getInstance(ek.toASN1Structure());
//			System.out.println("Issuer: " + iandsn.getName());
//			System.out.println("SN: " + iandsn.getCertificateSerialNumber());
			
			
			//---------
			// Get the EK CA Certificate
			//---------
			X509CertificateHolder ca = parseX509CertificateFromFile(ca_cert_filename);
			
			
            RSAKeyParameters pubkey = (RSAKeyParameters) PublicKeyFactory.createKey(ca.getSubjectPublicKeyInfo());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(pubkey.getModulus(), pubkey.getExponent());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pub = factory.generatePublic(spec);
            
            ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
            	    .setProvider("BC").build(pub);
            
            if(ek.isSignatureValid(contentVerifierProvider))
            {
            	System.out.println("Valid EK signature.");
    			System.exit(0);
            }
            else {
            	System.out.println("====\nInvalid EK signature!\n====\n");
    			System.exit(-1);
            }
		} 
		catch (FileNotFoundException e) {
			// Can't find file so we're done 
			System.out.println("ERROR: Can't find Certificate file!\n" + e.getLocalizedMessage());
			System.exit(-1);
		} 
		catch (IOException e) {
			System.out.println("WARNING: Failed parsing Certificate file\n" + e.getLocalizedMessage() );
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.exit(0);
//		System.exit(valid? 0: 1);
		
	}

	private static X509CertificateHolder parseX509CertificateFromFile(String filename) throws IOException
	{
		File file = new File(filename);
		FileReader fileReader = new FileReader(file);

		// first try to read as a PEM file
		Object loadedObj=TP_FileUtils.readPemFile(filename, true);
		
		if(loadedObj == null) {
			// failed to parse as PEM, try as DER (binary)
			System.out.println("Failed to parse X509Certificate from file " + file.getPath() + "; Not a valid PEM file!");
			System.out.println("Attempting to parse X509Certificate as a binary file.");
			byte[] fileBytes = Files.readAllBytes(file.toPath());
			loadedObj = new X509CertificateHolder(fileBytes);
		}
		
		return (X509CertificateHolder) loadedObj;
	}
}
