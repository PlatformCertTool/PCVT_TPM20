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
package com.trustiphi.tpm2verification;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.security.cert.CertificateException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.trustiphi.asn1.CommonCriteriaMeasures;
import com.trustiphi.asn1.ComponentAddress;
import com.trustiphi.asn1.ComponentIdentifier;
import com.trustiphi.asn1.FIPSLevel;
import com.trustiphi.asn1.ManufacturerId;
import com.trustiphi.asn1.PlatformConfiguration;
import com.trustiphi.asn1.Properties;
import com.trustiphi.asn1.TbbSecurityAssertions;
import com.trustiphi.asn1.TcgCredentialSpecification;
import com.trustiphi.asn1.TcgPlatformSpecification;
import com.trustiphi.asn1.URIReference;
import com.trustiphi.tpm2verification.platformcertparse.PlatformCertificateData;
import com.trustiphi.tpm2verification.platformcertparse.XmlCRLDistributionPoints;
import com.trustiphi.tpm2verification.platformcertparse.XmlCertificatePolicies;
import com.trustiphi.tpm2verification.platformcertparse.XmlCommonCriteriaMeasures;
import com.trustiphi.tpm2verification.platformcertparse.XmlComponentAddress;
import com.trustiphi.tpm2verification.platformcertparse.XmlComponentIdentifier;
import com.trustiphi.tpm2verification.platformcertparse.XmlDistributionPointName;
import com.trustiphi.tpm2verification.platformcertparse.XmlGeneralName;
import com.trustiphi.tpm2verification.platformcertparse.XmlGeneralNameTag;
import com.trustiphi.tpm2verification.platformcertparse.XmlPolicyQualifier;
import com.trustiphi.tpm2verification.platformcertparse.XmlProperties;
import com.trustiphi.tpm2verification.platformcertparse.XmlURIReference;

/**
 * @author Marshall Shapiro/TrustiPhi, LLC
 *
 */
public class PlatformCertificateHolder 
{
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_tcg_at_tcgPlatformSpecification = new ASN1ObjectIdentifier("2.23.133.2.17");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_tcg_at_tcgCredentialSpecification = new ASN1ObjectIdentifier("2.23.133.2.23");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_tcg_at_platformConfigUri = new ASN1ObjectIdentifier("2.23.133.5.1.3");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_tcg_at_platformConfiguration = new ASN1ObjectIdentifier("2.23.133.5.1.7");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_tcg_at_platformConfiguration_v1 = new ASN1ObjectIdentifier("2.23.133.5.1.7.1");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_tcg_at_tbbSecurityAssertions = new ASN1ObjectIdentifier("2.23.133.2.19");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_id_ce_certificatePolicies = new ASN1ObjectIdentifier("2.5.29.32");
	public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER_id_ce_CRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");

	public static final String DEFAULT_SIGNATURE_ALGORITHM = "Sha1WithRsa";
	
	/*
	 * Reset all the platform certificate information back to their initial values.
	 * (The initial values are generally null.)
	 * 
	 */
	public void clear()
	{
		issuer=null;
		attr_cert_holder=null;
		platform_cert_serial_num = null;
		notBefore=null;
		notAfter=null;
		tcgPlatformSpecification=null;
		tcgCredentialSpecification=null;
		tbbSecurityAssertions = null;
		certificate_policies=null;
		authorityKeyIdentifier=null;
		authorityInformationAccess=null;
		subjectAltName=null;
		cRLDistPoint=null;
		platformConfigUri=null;  
		signatureAlgorithm=null;
		signatureValue=null;
		privateKey=null;
		extIsCrticalCertificatePolicies=false;
		extIsCrticalSubjectAltName=false;
		extIsCrticalAuthKeyID=false;
		extIsCrticalAuthInfoAccess=false;
		extIsCrticalCrlDist=false;	
		dirtyBit = false;
	}
	
	public void setX509AttributeCertificateHolder(X509AttributeCertificateHolder x509attributeCertificateHolder)
	{
		this.attributeCertHolder = x509attributeCertificateHolder;
	}
	
	public X509AttributeCertificateHolder getX509AttributeCertificateHolder() 
	{
		return this.attributeCertHolder;
	}
		
	public AttributeCertificate getAttributeCertificate()
	{
		return this.attributeCertHolder.toASN1Structure();
	}

	public void loadFromFileDER(File file) throws IOException 
	{
		byte[] fileBytes = Files.readAllBytes(file.toPath());
		this.attributeCertHolder = new X509AttributeCertificateHolder(fileBytes);
		loadX509AttributeCertificateHolder(attributeCertHolder);
		dirtyBit = false;
	}
	
	public void loadFromFilePEM(File file) throws FileNotFoundException, IOException
	{
		FileReader fileReader = new FileReader(file);
		PEMParser pemParser = new PEMParser(fileReader);
		Object loadedObj = pemParser.readObject();
		pemParser.close();
		if(loadedObj == null) {
			throw new IOException("Failed to parse X509AttributeCertificate from file " + file.getPath() + "; Not a valid PEM file!");
		}
		
		if(!(loadedObj instanceof X509AttributeCertificateHolder) )
		{
			throw new IOException("Failed to parse X509AttributeCertificate from file " + file.getPath() + "; Cannot cast from type " + loadedObj.getClass().getSimpleName() + "!");
		}

		this.attributeCertHolder = (X509AttributeCertificateHolder) loadedObj;
		loadX509AttributeCertificateHolder(attributeCertHolder);
		dirtyBit = false;
	}
	
	public void writeToFileDER(File file) throws IOException, OperatorCreationException 
	{
		updateAsNeeded();
			
		if(this.attributeCertHolder != null)
		{
			Files.write(file.toPath(), this.attributeCertHolder.getEncoded());
		}
	}

	public void writeToFilePEM(File file) throws IOException, OperatorCreationException 
	{
		updateAsNeeded();
		
		if(this.attributeCertHolder != null)
		{
			TP_FileUtils.writePemFile("ATTRIBUTE CERTIFICATE", attributeCertHolder.getEncoded(), file, false);
		}
	}

	public void setPrivateKey(PrivateKey key)
	{
		this.privateKey = key;
	}
	
	public void loadFromJaxbObj(PlatformCertificateData platformCertificateData) 
	{
		// get the ACInfo Issuer 
		if(platformCertificateData.getIssuer() != null)
		{
			issuer = new AttributeCertificateIssuer(new X500Name(platformCertificateData.getIssuer()));
		}
		
		// get the Holder
		X500Name holder_ek_issuer=null;
		if(platformCertificateData.getEKIssuer() != null)
		{
			holder_ek_issuer = new X500Name(platformCertificateData.getEKIssuer());
		} 

		BigInteger holder_ek_serialnum=null;
		if(platformCertificateData.getEKCertSerialNumber() != null)
		{
			holder_ek_serialnum = new BigInteger(platformCertificateData.getEKCertSerialNumber(), 16);
			attr_cert_holder = new AttributeCertificateHolder(holder_ek_issuer, holder_ek_serialnum);
		} 
		else {
			if(holder_ek_issuer != null)
			{
				attr_cert_holder = new AttributeCertificateHolder(holder_ek_issuer);
			}
		}
		
		// get the platform serial number, not before date and not after date
		if(platformCertificateData.getPlatformCertSerialNumber() != null)
		{
			platform_cert_serial_num = new BigInteger(platformCertificateData.getPlatformCertSerialNumber(), 16);
		}

		if(platformCertificateData.getValidFrom() != null)
		{
			notBefore = platformCertificateData.getValidFrom().toGregorianCalendar().getTime();
		}
		
		if(platformCertificateData.getValidTo() != null)
		{
			notAfter = platformCertificateData.getValidTo().toGregorianCalendar().getTime();
		}
		
		// Set the attributes TCG PlatformSpecification and TBB Security Assertions
		
		// Set attribute TCG PlatformSpecification
		TcgPlatformSpecification t_tcgPlatformSpecification = extract_TcgPlatformSpecification(platformCertificateData);
		if(t_tcgPlatformSpecification != null)
		{
			tcgPlatformSpecification = t_tcgPlatformSpecification;
		}
		
		// Set attribute TCG CredentialSpecification
	    TcgCredentialSpecification t_tcgCredentialSpecification = extract_TcgCredentialSpecification(platformCertificateData);
        if(t_tcgCredentialSpecification != null)
        {
            tcgCredentialSpecification = t_tcgCredentialSpecification;
        }
		
		// Set attribute TBB Security Assertions
		TbbSecurityAssertions t_tbbSecurityAssertions = extract_TbbSecurityAssertions(platformCertificateData);
		if(t_tbbSecurityAssertions != null)
		{
			tbbSecurityAssertions = t_tbbSecurityAssertions;
		}
		
		// Set attribute Platform Configuration Uri
		URIReference t_platformConfigUri = extract_PlatformConfigUri(platformCertificateData);
		if (t_platformConfigUri != null)
		{
		    platformConfigUri = t_platformConfigUri;
		}
		
		// Set attribute Platform Configuration
        PlatformConfiguration t_platformConfiguration = extract_PlatformConfiguration(platformCertificateData);
        if (t_platformConfiguration != null)
        {
            platformConfiguration = t_platformConfiguration;
        }
		
		// add the extensions CertificatePolicies, authorityKeyIdentifier, authorityInfoAccess, subjectAlternativeName, CRLDistPoint
		
		CertificatePolicies t_certificate_policies = extract_CertificatePolicies(platformCertificateData);
		if(t_certificate_policies != null)
		{
			certificate_policies = t_certificate_policies;
		}
		
		AuthorityKeyIdentifier t_authorityKeyIdentifier = extract_AuthorityKeyIdentifier(platformCertificateData);
		if(t_authorityKeyIdentifier != null)
		{
			authorityKeyIdentifier = t_authorityKeyIdentifier;
		}
		
		AuthorityInformationAccess t_authorityInformationAccess = extract_AuthorityInformationAccess(platformCertificateData);
		if(t_authorityInformationAccess != null)
		{
			authorityInformationAccess = t_authorityInformationAccess;
		}
		
		GeneralNames t_subjectAltName = extract_PlatformInformation(platformCertificateData);
		if(t_subjectAltName != null)
		{
			subjectAltName = t_subjectAltName;
		}
		
		CRLDistPoint t_cRLDistPoint = extract_CRLDistPoint(platformCertificateData);
		if(t_cRLDistPoint != null)
		{
		    cRLDistPoint = t_cRLDistPoint;
		}
		
		// get the signature algorithm and value
		String t_signatureAlgorithm = platformCertificateData.getSignatureAlgorithm();
		if(t_signatureAlgorithm != null)
		{
			signatureAlgorithm = t_signatureAlgorithm;
		}
		
		byte[] t_signatureValue = platformCertificateData.getSignatureValue();
		if(t_signatureValue != null)
		{
			this.signatureValue = t_signatureValue;
		}
		
		dirtyBit = true;
	}

	public PlatformCertificateData toJaxbObj() 
	{
		PlatformCertificateData platformCertificateData = new PlatformCertificateData();
		
		// set the ACInfo Issuer
		if(this.issuer != null)
		{
			X500Name[] issuerNames =  this.issuer.getNames();
			if(issuerNames.length > 0 && issuerNames[0] != null)
			{
				platformCertificateData.setIssuer(TrustiPhiStyle.INSTANCE.toString(issuerNames[0]));
			}
		}
		
		// set the Holder
		if(this.attr_cert_holder != null)
		{
			X500Name[] holderIssuerNames =  this.attr_cert_holder.getIssuer();
			if(holderIssuerNames != null && holderIssuerNames.length > 0 && holderIssuerNames[0] != null)
			{
				platformCertificateData.setEKIssuer(TrustiPhiStyle.INSTANCE.toString(holderIssuerNames[0]));
			}
			
			BigInteger holderIssuerSN = this.attr_cert_holder.getSerialNumber();
			if(holderIssuerSN != null)
			{
				platformCertificateData.setEKCertSerialNumber(holderIssuerSN.toString(16));
			}
		}
		
		// get the platform serial number, not before date and not after date
		if(platform_cert_serial_num != null)
		{
			platformCertificateData.setPlatformCertSerialNumber(platform_cert_serial_num.toString(16));
		}

		if(notBefore != null)
		{
			try {
				GregorianCalendar gc = new GregorianCalendar();
				gc.setTime(notBefore);
				XMLGregorianCalendar xmlValidFrom;
				xmlValidFrom = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);

				platformCertificateData.setValidFrom(xmlValidFrom);
			} 
			catch (DatatypeConfigurationException e) {
				// TODO Auto-generated catch block
				LOG_ERRROR("toJaxbObj", "Failed to set ValidFromDate!");
				e.printStackTrace();
			}			

		}
		
		if(notAfter != null)
		{
			try {
				GregorianCalendar gc = new GregorianCalendar();
				gc.setTime(notAfter);
				XMLGregorianCalendar xmlValidTo;
				xmlValidTo = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
				
				platformCertificateData.setValidTo(xmlValidTo);
			} 
			catch (DatatypeConfigurationException e) {
				// TODO Auto-generated catch block
				LOG_ERRROR("toJaxbObj", "Failed to set ValidFromTo!");
				e.printStackTrace();
			}			

		}
		
		// Set the attributes TCG PlatformSpecification and TBB Security Assertions
		
		// Set attribute TCG PlatformSpecification
		set_TcgPlatformSpecificationFields(platformCertificateData);
		
	    // Set attribute TCG CredentialSpecification
        set_TcgCredentialSpecificationFields(platformCertificateData);
				
		// Set attribute TBB Security Assertions
		set_TbbSecurityAssertionsFields(platformCertificateData);
		
		// Set attribute Platform Configuration Uri
		set_PlatformConfigUri(platformCertificateData);
		
	    // Set attribute Platform Configuration
        set_PlatformConfiguration(platformCertificateData);
		
		// add the extensions CertificatePolicies, authorityKeyIdentifier, authorityInfoAccess, subjectAlternativeName, CRLDistPoint
		
		set_CertificatePoliciesFields(platformCertificateData);
		
		set_AuthorityKeyIdentifier(platformCertificateData);
		
		set_AuthorityInformationAccess(platformCertificateData);
		
		set_PlatformInformation(platformCertificateData);
		
		set_CRLDistPointFields(platformCertificateData);
		
		// set the signature algorithm 
		if(signatureAlgorithm != null)
		{
			// the signatureAlgorithm string may contain the OID of the algorithm or the name.
			// try  to output as the name for readability.
			String signatureAlgorithm_out;
			try {
				ASN1ObjectIdentifier signatureAlgOid = new ASN1ObjectIdentifier(signatureAlgorithm);
				DefaultAlgorithmNameFinder algNameFinder = new DefaultAlgorithmNameFinder();
				if(algNameFinder.hasAlgorithmName(signatureAlgOid))
				{
					signatureAlgorithm_out = algNameFinder.getAlgorithmName(signatureAlgOid);
				}
				else {
					signatureAlgorithm_out = signatureAlgorithm;
				}
			}
			catch(IllegalArgumentException x)
			{
				// not a valid OID
				signatureAlgorithm_out = signatureAlgorithm;
			}
			platformCertificateData.setSignatureAlgorithm(signatureAlgorithm_out);
		}
		
		if(signatureValue != null)
		{
			platformCertificateData.setSignatureValue(signatureValue);
		}
		
		return platformCertificateData;
	}

	private void updatePlatformCertificateHolder(PrivateKey privateKey) 
			throws CertIOException, OperatorCreationException
	{
/////////
//
//  Commenting out code to create default values for required Attribute Certificate fields
//  Perhaps this will be added back in later.  First need to determine if there is a valid use case for this.
//
//		// get the ACInfo Issuer 
//		AttributeCertificateIssuer issuer_to_use=null;
//		if(issuer != null)
//		{
//			issuer_to_use = issuer;
//		}
//		else {
//			issuer = new AttributeCertificateIssuer(new X500Name(""));
//		}
//		
//		// get the Holder
//		AttributeCertificateHolder attr_cert_holder_to_use=null;
//		if(attr_cert_holder != null)
//		{
//			attr_cert_holder_to_use = attr_cert_holder;
//		}
//		else {
//			attr_cert_holder_to_use = new AttributeCertificateHolder(new X500Name(""));
//		}
//		
//		// get the platform serial number, not before date and not after date
//		BigInteger platform_serial_num_to_use = null;
//		if(platform_serial_num != null)
//		{
//			platform_serial_num_to_use = platform_serial_num;
//		}
//
//		Date notBefore_to_use=null;
//		if(notBefore != null)
//		{
//			notBefore_to_use = notBefore;
//		}
//		
//		Date notAfter_to_use=null;
//		if(notAfter != null)
//		{
//			notAfter_to_use = notAfter;
//		}
////////
		
		// Make sure we have the minimum required inputs before creating the certificate builder
		if(attr_cert_holder == null)
		{
			LOG_ERRROR("updatePlatformCertificateHolder", "Missing required information: AttributeCertificateHolder! Unable to create X509v2AttributeCertificate!");
			throw new CertIOException("Missing required information AttributeCertificateHolder");
		}

		if(issuer == null)
		{
			LOG_ERRROR("updatePlatformCertificateHolder", "Missing required information: Issuer! Unable to create X509v2AttributeCertificate!");
			throw new CertIOException("Missing required information Issuer");
		}

		if(platform_cert_serial_num == null)
		{
			LOG_ERRROR("updatePlatformCertificateHolder", "Missing required information: Platform Certificate Serial Number! Unable to create X509v2AttributeCertificate!");
			throw new CertIOException("Missing required information Platform Certificate Serial Number");
		}

		if(notBefore == null)
		{
			LOG_ERRROR("updatePlatformCertificateHolder", "Missing required information: Not Before Date! Unable to create X509v2AttributeCertificate!");
			throw new CertIOException("Missing required information Not Before Date");
		}

		if(notAfter == null)
		{
			LOG_ERRROR("updatePlatformCertificateHolder", "Missing required information: Not Before Date! Unable to create X509v2AttributeCertificate!");
			throw new CertIOException("Missing required information Not After Date");
		}

		// create the certificate builder and then add the attributes and extensions
		X509v2AttributeCertificateBuilder certBuilder = 
				new X509v2AttributeCertificateBuilder(attr_cert_holder,
						                              issuer, 
						                              platform_cert_serial_num, 
						                              notBefore, 
						                              notAfter);
		
		
		// add the attributes
		Attribute attr;

		// Add attribute TCG PlatformSpecification
		if(tcgPlatformSpecification != null)
		{
			attr = new Attribute(OBJECT_IDENTIFIER_tcg_at_tcgPlatformSpecification, new DLSet(tcgPlatformSpecification));
			certBuilder.addAttribute(attr.getAttrType(), attr.getAttributeValues());
		}
		
	    // Add attribute TCG CredentialSpecification
        if(tcgCredentialSpecification != null)
        {
            attr = new Attribute(OBJECT_IDENTIFIER_tcg_at_tcgCredentialSpecification, new DLSet(tcgCredentialSpecification));
            certBuilder.addAttribute(attr.getAttrType(), attr.getAttributeValues());
        }

		
		// Add attribute TBB Security Assertions
		if(tbbSecurityAssertions != null)
		{
			attr = new Attribute(OBJECT_IDENTIFIER_tcg_at_tbbSecurityAssertions, new DLSet(tbbSecurityAssertions));
			certBuilder.addAttribute(attr.getAttrType(), attr.getAttributeValues());
		}
		
		// Add attribute Platform Configuration Uri
		if (platformConfigUri != null)
		{
		    attr = new Attribute(OBJECT_IDENTIFIER_tcg_at_platformConfigUri, new DLSet(platformConfigUri));
            certBuilder.addAttribute(attr.getAttrType(), attr.getAttributeValues());
		}
		
		// Add attribute Platform Configuration
        if (platformConfiguration != null)
        {
            attr = new Attribute(OBJECT_IDENTIFIER_tcg_at_platformConfiguration_v1, new DLSet(platformConfiguration));
            certBuilder.addAttribute(attr.getAttrType(), attr.getAttributeValues());
        }
		
		// add the extensions
		
		// get the certificate policies and it to the extensions if it's there
		if(certificate_policies != null)
		{
			certBuilder.addExtension(OBJECT_IDENTIFIER_id_ce_certificatePolicies, false, certificate_policies);
		}
		
		if(authorityKeyIdentifier != null)
		{
			certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
		}
		
		if(authorityInformationAccess != null)
		{
			certBuilder.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
		}
		
		if(subjectAltName != null)
		{
			certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
		}
		if(cRLDistPoint != null)
		{
			certBuilder.addExtension(Extension.cRLDistributionPoints, false, cRLDistPoint);
		}
		
		// get the signature algorithm 
		String signatureAlgorithm_to_use;
		if(signatureAlgorithm == null)
		{
			signatureAlgorithm_to_use = DEFAULT_SIGNATURE_ALGORITHM;
		}
		else {			
			// the signatureAlgorithm string in the XML may contain the OID of the algorithm or the name
			// of the algorithm. try as an OID and if an exception is thrown use assume it is a name.
			try {
				ASN1ObjectIdentifier signatureAlgOid = new ASN1ObjectIdentifier(signatureAlgorithm);
				DefaultAlgorithmNameFinder algNameFinder = new DefaultAlgorithmNameFinder();
				if(algNameFinder.hasAlgorithmName(signatureAlgOid))
				{
					signatureAlgorithm_to_use = algNameFinder.getAlgorithmName(signatureAlgOid);
				}
				else {
					signatureAlgorithm_to_use = signatureAlgorithm;
				}
			}
			catch(IllegalArgumentException x)
			{
				// not a valid OID
				signatureAlgorithm_to_use = signatureAlgorithm;
			}
		}

		// create the content signer using the input private key (and the algorithm found in the PlatformCertificateData)
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm_to_use).build(privateKey);

		attributeCertHolder = certBuilder.build(signer);

		// the signature has been updated
		signatureValue = attributeCertHolder.getSignature();
		
		dirtyBit = false;
	}

	
	private void loadX509AttributeCertificateHolder(X509AttributeCertificateHolder x509AttrCertHolder) 
	{
		// get the ACInfo Issuer 
		issuer = x509AttrCertHolder.getIssuer();
		
		// get the Holder
		attr_cert_holder = x509AttrCertHolder.getHolder();
		
		// get the platform serial number, not before date and not after date
		platform_cert_serial_num = x509AttrCertHolder.getSerialNumber();
		notBefore = x509AttrCertHolder.getNotBefore();
		notAfter = x509AttrCertHolder.getNotAfter();
				
		// Get the attributes TCG PlatformSpecification and TBB Security Assertions
		
		// Get attribute TCG PlatformSpecification, if there is more than one, only use the first one!
		tcgPlatformSpecification = extract_TcgPlatformSpecification(x509AttrCertHolder);
		
	    // Get attribute TCG CredentialSpecification, if there is more than one, only use the first one!
        tcgCredentialSpecification = extract_TcgCredentialSpecification(x509AttrCertHolder);
		
		// Set attribute TBB Security Assertions
		tbbSecurityAssertions = extract_TbbSecurityAssertions(x509AttrCertHolder);
		
		// Set attribute Platform Configuration Uri
		platformConfigUri = extract_PlatformConfigUri(x509AttrCertHolder);
		
        // Set attribute Platform Configuration
        platformConfiguration = extract_PlatformConfiguration(x509AttrCertHolder);
		
		// add the extensions CertificatePolicies, authorityKeyIdentifier, authorityInfoAccess, subjectAlternativeName, CRLDistPoint
		certificate_policies = CertificatePolicies.fromExtensions(x509AttrCertHolder.getExtensions());
		
		authorityKeyIdentifier = AuthorityKeyIdentifier.fromExtensions(x509AttrCertHolder.getExtensions());
		
		authorityInformationAccess = AuthorityInformationAccess.fromExtensions(x509AttrCertHolder.getExtensions());
		
		subjectAltName = GeneralNames.fromExtensions(x509AttrCertHolder.getExtensions(),Extension.subjectAlternativeName);
		
		cRLDistPoint = extract_CRLDistPoint(x509AttrCertHolder);
		
		// get the signature algorithm 
		signatureAlgorithm = x509AttrCertHolder.getSignatureAlgorithm().getAlgorithm().toString();
		
		signatureValue = x509AttrCertHolder.getSignature();
	}

	
	public boolean verifySignature(PublicKey publicKey) 
			throws OperatorCreationException, IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		updateAsNeeded();
		
		AttributeCertificate attributeCertificate = getAttributeCertificate();
		
		// make sure the signature algorithm on the attribute certificate (outer most ASN1 layer)
		// matches the algorithm in the ACINfo (AttributeCertificateInformation) section of the 
		// certificate.
		// If are different something is wrong because they refer to the same signature
		if(!attributeCertificate.getSignatureAlgorithm().equals(
				attributeCertificate.getAcinfo().getSignature()))
		{
			throw new CertificateException("Mismatched AttributeCertificate values: Signature algorithm in the AttrubuteCertificate is different than algorithm in the ACInfo section (" 
							+ attributeCertificate.getSignatureAlgorithm().getAlgorithm().toString() + " <> "
					        + attributeCertificate.getAcinfo().getSignature().getAlgorithm().toString() + ")");
		}

		Signature signature = Signature.getInstance(
				attributeCertificate.getSignatureAlgorithm().getAlgorithm().getId());
		
		signature.initVerify(publicKey);
		
		signature.update(attributeCertificate.getAcinfo().getEncoded());

		return signature.verify(signatureValue);
	}
	
	/***
	 * Extract the tcg-PlatformSpecification information from the PlatformCertificateData object
	 * and return a TcgPlatformSpecification initialized with that information.
	 * 
	 * If the platformCertificateData does not contain any PlatformSpecification fields return null.
	 * 
	 * @param platformCertificateData
	 * @return TcgPlatformSpecification initialized with that information, or null if no tcgPlatformSpecification fields found
	 */
	private TcgPlatformSpecification extract_TcgPlatformSpecification(PlatformCertificateData platformCertificateData)
	{
		String  platformSpec_platform_class = platformCertificateData.getPlatformClass();
		Integer platformSpec_major_ver = platformCertificateData.getMajorVersion();
		Integer platformSpec_minor_ver = platformCertificateData.getMinorVersion();
		Integer platformSpec_rev = platformCertificateData.getRevision();

		// no Platform SPecification to return so just return null
		if(platformSpec_platform_class == null && 
           platformSpec_major_ver == null && 
           platformSpec_minor_ver == null &&
           platformSpec_rev == null)
		{
			return null;
		}
		
		TcgPlatformSpecification tcgPlatformSpecification = 
				new TcgPlatformSpecification(platformSpec_platform_class, 
						                     platformSpec_major_ver, 
						                     platformSpec_minor_ver, 
						                     platformSpec_rev);
		
		return tcgPlatformSpecification;
	}
	
	/***
	 * Extract the tcg-PlatformSpecification information from X509AttributeCertificateHolder
	 * and return a TcgPlatformSpecification initialized with that information.
	 * 
	 * If the X509AttributeCertificateHolder does not contain any PlatformSpecification fields return null.
	 * 
	 * @param platformCertificateData
	 * @return TcgPlatformSpecification initialized with that information, or null if no tcgPlatformSpecification fields found
	 */
	private TcgPlatformSpecification extract_TcgPlatformSpecification(X509AttributeCertificateHolder x509AttrCertHolder)
	{
		TcgPlatformSpecification retTcgPlatformSpec = null;
		
		Attribute attributes[] = x509AttrCertHolder.getAttributes(OBJECT_IDENTIFIER_tcg_at_tcgPlatformSpecification);
		if(attributes.length > 0)
		{
			ASN1Set tcgPlatformSpecAttrSet = attributes[0].getAttrValues();
			if(tcgPlatformSpecAttrSet != null && tcgPlatformSpecAttrSet.toArray().length > 0)
			{
				try {
					retTcgPlatformSpec = new TcgPlatformSpecification(tcgPlatformSpecAttrSet.toArray()[0]);
				} catch (IOException e) {
					LOG_ERRROR("extract_tcgPlatformSpecification", e.getMessage());
				}
			}
		}
		
		return retTcgPlatformSpec;
	}
	
	/***
     * Extract the tcg-CredentialSpecification information from the PlatformCertificateData object
     * and return a TcgCredentialSpecification initialized with that information.
     * 
     * If the platformCertificateData does not contain any CredentialSpecification fields return null.
     * 
     * @param platformCertificateData
     * @return TcgCredentialSpecification initialized with that information, or null if no tcgCredentialSpecification fields found
     */
    private TcgCredentialSpecification extract_TcgCredentialSpecification(PlatformCertificateData platformCertificateData)
    {
        Integer credentialSpec_major_ver = platformCertificateData.getTcgCredentialSpecificationMajorVersion();
        Integer credentialSpec_minor_ver = platformCertificateData.getTcgCredentialSpecificationMinorVersion();
        Integer credentialSpec_rev = platformCertificateData.getTcgCredentialSpecificationRevision();

        // no Credential SPecification to return so just return null
        if(credentialSpec_major_ver == null && 
                credentialSpec_minor_ver == null &&
                credentialSpec_rev == null)
        {
            return null;
        }
        
        TcgCredentialSpecification tcgCredentialSpecification = 
                new TcgCredentialSpecification(credentialSpec_major_ver, 
                                    credentialSpec_minor_ver, 
                                    credentialSpec_rev);
        
        return tcgCredentialSpecification;
    }
    
    /***
     * Extract the tcg-CredentialSpecification information from X509AttributeCertificateHolder
     * and return a TcgCredentialSpecification initialized with that information.
     * 
     * If the X509AttributeCertificateHolder does not contain any CredentialSpecification fields return null.
     * 
     * @param x509AttrCertHolder
     * @return TcgCredentialSpecification initialized with that information, or null if no tcgCredentialSpecification fields found
     */
    private TcgCredentialSpecification extract_TcgCredentialSpecification(X509AttributeCertificateHolder x509AttrCertHolder)
    {
        TcgCredentialSpecification retTcgCredentialSpec = null;
        
        Attribute attributes[] = x509AttrCertHolder.getAttributes(OBJECT_IDENTIFIER_tcg_at_tcgCredentialSpecification);
        if(attributes.length > 0)
        {
            ASN1Set tcgCredentialSpecAttrSet = attributes[0].getAttrValues();
            if(tcgCredentialSpecAttrSet != null && tcgCredentialSpecAttrSet.toArray().length > 0)
            {
                try {
                    retTcgCredentialSpec = new TcgCredentialSpecification(tcgCredentialSpecAttrSet.toArray()[0]);
                } catch (IOException e) {
                    LOG_ERRROR("extract_TcgCredentialSpecification", e.getMessage());
                }
            }
        }
        
        return retTcgCredentialSpec;
    }
    
    /***
     * Extract the PlatformConfigUri information from the PlatformCertificateData object
     * and return a URIReference initialized with that information.
     * 
     * If the platformCertificateData does not contain any PlatformConfigUri fields return null.
     * 
     * @param platformCertificateData
     * @return TcgCredentialSpecification initialized with that information, or null if no PlatformConfigUri fields found
     */
    private URIReference extract_PlatformConfigUri(PlatformCertificateData platformCertificateData)
    {
        URIReference retPlatformConfigUri = null;
        
        if(platformCertificateData.getPlatformConfigUri() != null)
        {
            XmlURIReference platformConfigUriInfo =
                    platformCertificateData.getPlatformConfigUri();
            
            String uriRef_uriRefId = platformConfigUriInfo.getUniformResourceIdentifier();
            String uriRef_hashAlg = platformConfigUriInfo.getHashAlgorithm();
            byte[] uriRef_hashVal = platformConfigUriInfo.getHashValue();
            
            retPlatformConfigUri = new URIReference();
            if(uriRef_uriRefId != null)
            {
                retPlatformConfigUri.setUniformResourceIdentifier(new DERIA5String(uriRef_uriRefId));
            }
            
            if(uriRef_hashAlg != null)
            {
                retPlatformConfigUri.setHashAlgorithm(new AlgorithmIdentifier(new ASN1ObjectIdentifier(uriRef_hashAlg)));
            }
            
            if(uriRef_hashVal != null)
            {
                retPlatformConfigUri.setHashValue(new DERBitString(uriRef_hashVal));
            }           
        }        
        
        return retPlatformConfigUri;
    }
    
    /***
     * Extract the PlatformConfigUri information from X509AttributeCertificateHolder
     * and return a URIReference initialized with that information.
     * 
     * If the X509AttributeCertificateHolder does not contain any PlatformConfigUri fields return null.
     * 
     * @param x509AttrCertHolder
     * @return URIReference initialized with that information, or null if no PlatformConfigUri fields found
     */
    private URIReference extract_PlatformConfigUri(X509AttributeCertificateHolder x509AttrCertHolder)
    {
        URIReference retPlatformConfigUri = null;
        
        Attribute attributes[] = x509AttrCertHolder.getAttributes(OBJECT_IDENTIFIER_tcg_at_platformConfigUri);
        if(attributes.length > 0)
        {
            ASN1Set platformConfigUriAttrSet = attributes[0].getAttrValues();
            if(platformConfigUriAttrSet != null && platformConfigUriAttrSet.toArray().length > 0)
            {
                try {
                    retPlatformConfigUri = new URIReference(platformConfigUriAttrSet.toArray()[0]);
                } catch (IOException e) {
                    LOG_ERRROR("extract_PlatformConfigUri", e.getMessage());
                }
            }
        }
        
        return retPlatformConfigUri;
    }
    
    /***
     * Extract the PlatformConfiguration information from the PlatformCertificateData object
     * and return a PlatformConfiguration initialized with that information.
     * 
     * If the platformCertificateData does not contain any PlatformConfiguration fields return null.
     * 
     * @param platformCertificateData
     * @return PlatformConfiguration initialized with that information, or null if no PlatformConfiguration fields found
     */
    private PlatformConfiguration extract_PlatformConfiguration(PlatformCertificateData platformCertificateData)
    {
        ComponentIdentifier[] componentIdentifier = null;
        Properties[] platformProperties = null;
        URIReference platformPropertiesUri = null;        
        
        // ComponentIdentifier
        if (platformCertificateData.getComponentIdentifier() != null 
                && platformCertificateData.getComponentIdentifier().size() > 0)
        {
            List<XmlComponentIdentifier> componentIdentififierInfo = platformCertificateData.getComponentIdentifier();
            componentIdentifier = new ComponentIdentifier[componentIdentififierInfo.size()];
            
            int i = 0;
            for (XmlComponentIdentifier xmlComponentIdentifier : componentIdentififierInfo)
            {
                componentIdentifier[i] = new ComponentIdentifier();
                        
                if (xmlComponentIdentifier != null)
                {
                    if (xmlComponentIdentifier.getComponentManufacturer() != null)
                    {
                        componentIdentifier[i].setComponentManufacturer(xmlComponentIdentifier.getComponentManufacturer());
                    }
                    if (xmlComponentIdentifier.getComponentModel() != null)
                    {
                        componentIdentifier[i].setComponentModel(xmlComponentIdentifier.getComponentModel());
                    }                    
                    if (xmlComponentIdentifier.getComponentSerial() != null)
                    {
                        componentIdentifier[i].setComponentSerial(xmlComponentIdentifier.getComponentSerial());
                    }
                    if (xmlComponentIdentifier.getComponentRevision() != null)
                    {
                        componentIdentifier[i].setComponentRevision(xmlComponentIdentifier.getComponentRevision());
                    }
                    if (xmlComponentIdentifier.getComponentManufacturerId() != null)
                    {
                        componentIdentifier[i].setComponentManufacturerId(new ASN1ObjectIdentifier(
                                xmlComponentIdentifier.getComponentManufacturerId()));
                    }
                    if (xmlComponentIdentifier.isFieldReplaceable() != null)
                    {
                        componentIdentifier[i].setFieldReplaceable(xmlComponentIdentifier.isFieldReplaceable());
                    }
                    if (xmlComponentIdentifier.getComponentAddress() != null 
                            && xmlComponentIdentifier.getComponentAddress().size() > 0)
                    {
                        List<XmlComponentAddress> componentAddressInfo = xmlComponentIdentifier.getComponentAddress();
                        ComponentAddress[] componentAddress = new ComponentAddress[componentAddressInfo.size()];
                        
                        int j = 0;
                        for (XmlComponentAddress xmlComponentAddress : componentAddressInfo)
                        {
                            componentAddress[j] = new ComponentAddress();
                            
                            if (xmlComponentAddress != null)
                            {
                                if (xmlComponentAddress.getAddressType() != null)
                                {
                                    componentAddress[j].setAddressType(new ASN1ObjectIdentifier(
                                            xmlComponentAddress.getAddressType()));
                                }
                                if (xmlComponentAddress.getAddressValue() != null)
                                {
                                    componentAddress[j].setAddressValue(xmlComponentAddress.getAddressValue());
                                }
                            }
                            j++;
                        }
                        componentIdentifier[i].setComponentAddress(componentAddress);
                    }
                }
                i++;
            }
        }
        
        // PlatformProperties
        if (platformCertificateData.getPlatformProperties() != null 
                && platformCertificateData.getPlatformProperties().size() > 0)
        {
            List<XmlProperties> platformPropertiesInfo = platformCertificateData.getPlatformProperties();
            platformProperties = new Properties[platformPropertiesInfo.size()];
            
            int i = 0;
            for (XmlProperties xmlProperties : platformPropertiesInfo)
            {
                platformProperties[i] = new Properties();
                
                if (xmlProperties != null)
                {
                    if (xmlProperties.getPropertyName() != null)
                    {
                        platformProperties[i].setPropertyName(xmlProperties.getPropertyName());
                    }
                    if (xmlProperties.getPropertyValue() != null)
                    {
                        platformProperties[i].setPropertyValue(xmlProperties.getPropertyValue());
                    }  
                }
                i++;
            }
        }
        
        // PlatformPropertiesUri
        if (platformCertificateData.getPlatformPropertiesUri() != null)
        {
            XmlURIReference platformPropertiesUriInfo = platformCertificateData.getPlatformPropertiesUri();
            platformPropertiesUri = new URIReference();
            
            if(platformPropertiesUriInfo.getUniformResourceIdentifier() != null)
            {
                platformPropertiesUri.setUniformResourceIdentifier(
                        new DERIA5String(platformPropertiesUriInfo.getUniformResourceIdentifier()));
            }
            
            if(platformPropertiesUriInfo.getHashAlgorithm() != null)
            {
                platformPropertiesUri.setHashAlgorithm(
                        new AlgorithmIdentifier(new ASN1ObjectIdentifier(platformPropertiesUriInfo.getHashAlgorithm())));
            }
            
            if(platformPropertiesUriInfo.getHashValue() != null)
            {
                platformPropertiesUri.setHashValue(new DERBitString(platformPropertiesUriInfo.getHashValue()));
            }
        }
        
        if (componentIdentifier == null
                && platformProperties == null
                && platformPropertiesUri == null)
        {
            return null;
        }
        else {
            return  new PlatformConfiguration(componentIdentifier, platformProperties, platformPropertiesUri);
        }     
    }
    
    /***
     * Extract the PlatformConfiguration information from X509AttributeCertificateHolder
     * and return a PlatformConfiguration initialized with that information.
     * 
     * If the X509AttributeCertificateHolder does not contain any PlatformConfiguration fields return null.
     * 
     * @param x509AttrCertHolder
     * @return PlatformConfiguration initialized with that information, or null if no PlatformConfiguration fields found
     */
    private PlatformConfiguration extract_PlatformConfiguration(X509AttributeCertificateHolder x509AttrCertHolder)
    {
        PlatformConfiguration retPlatformConfiguration = null;
        
        Attribute[] attributes = x509AttrCertHolder.getAttributes(OBJECT_IDENTIFIER_tcg_at_platformConfiguration);
        if(attributes.length <= 0)
        {
            attributes = x509AttrCertHolder.getAttributes(OBJECT_IDENTIFIER_tcg_at_platformConfiguration_v1);
        }
        if(attributes.length > 0)
        {
            ASN1Set platformConfigurationAttrSet = attributes[0].getAttrValues();
            if(platformConfigurationAttrSet != null && platformConfigurationAttrSet.toArray().length > 0)
            {
                try {
                    retPlatformConfiguration = new PlatformConfiguration(platformConfigurationAttrSet.toArray()[0]);
                } catch (IOException e) {
                    LOG_ERRROR("extract_PlatformConfiguration", e.getMessage());
                }
            }
        }
        
        return retPlatformConfiguration;
    }
	
	/**
	 * Create and return a CertificatePolicies ASN1 object given the JAXB representation
	 * 
	 * The following is the defined format of a CertficatePolicies structure:
	 * 
	 * certificatePolicies EXTENSION ::= {
	 *   	SYNTAX CertificatePoliciesSyntax
	 *   	IDENTIFIED BY id-ce-certificatePolicies
	 *   }
	 *   
	 *   CertificatePoliciesSyntax ::= SEQUENCE SIZE (1..MAX) OF
	 *   	PolicyInformation
	 *   
	 *   PolicyInformation ::= SEQUENCE {
	 *   	policyIdentifier CertPolicyId,
	 *   	policyQualifier SEQUENCE SIZE (1..MAX) OF
	 *   		PolicyQualifierInfo OPTIONAL
	 *   }
	 *   
	 *   CertPolicyId ::= OBJECT IDENTIFIER
	 *   
	 *   PolicyQualiferInfo ::= SEQUENCE {
	 *   	policyQualifierId CERT-POLICY-QUALIFIER.&id
	 *   			({SupportedPolicyQualifiers}),
	 *   	qualifier CERT-POLICY-QUALIFIER.&Qualifier
	 *   			({SupportedPolicyQualifiers}
	 *   			 { at policyQualifierId}) 
	 *   			OPTIONAL
	 *   }
	 *   
	 *   SupportedPolicyQualifers CERT-POLICY-QUALIFIER ::= { ... }
	 *   
	 *   CERT-POLICY-QUALIFIER ::= CLASS {
	 *   	&id	OBJECT IDENTIFIER UNIQUE,
	 *   	&Qualifier OPTIONAL
	 *   } WITH SYNTAX {
	 *   	POLICY-QUALIFIER-ID &id
	 *   	[QUALIFIER-TYPE &Qualifier]
	 *   }
	 *   
	 *   
	 * @param platformCertificateData a JAXB representation of a PlatfromCertificate
	 * 
	 * @return an ASN1 representation of a CertificatePolicies 
	 *         or NULL if Certificate Policies id not found in the input structure
	 */
	private CertificatePolicies extract_CertificatePolicies(PlatformCertificateData platformCertificateData)
	{
		if(platformCertificateData.getCertificatePolicies() == null || platformCertificateData.getCertificatePolicies().isEmpty())
		{
			return null;
		}
		
		
		
		PolicyInformation[] policyInfoArray = 
				new PolicyInformation[platformCertificateData.getCertificatePolicies().size()];
		
		int policyInfoArray_idx=0;
		for(XmlCertificatePolicies certPolicies: platformCertificateData.getCertificatePolicies())
		{
			String policyIdStr = certPolicies.getPolicyIdentifier();
			ASN1ObjectIdentifier policyIdentifier = new ASN1ObjectIdentifier(policyIdStr);
			
			
			// create the policyQualifiers array
			ASN1EncodableVector policyQualsArray = new ASN1EncodableVector();
			
			for(XmlPolicyQualifier policyQualifier: certPolicies.getPolicyQualifier())
			{
				String qualifierIdStr = policyQualifier.getPolicyQualifierId();
				ASN1ObjectIdentifier qualifierId = new ASN1ObjectIdentifier(qualifierIdStr);
				
				String qualifierStr = policyQualifier.getQualifier();
				ASN1Encodable qualifier = null;
				
				if(PolicyQualifierId.id_qt_cps.equals(qualifierId))
				{
					qualifier = new DERIA5String(qualifierStr);
				} 
				else if(PolicyQualifierId.id_qt_unotice.equals(qualifierId)) 
				{
					qualifier = new UserNotice(null, qualifierStr);
				} 
				else {
					// ERROR
					LOG_ERRROR("extract_CertificatePolicies", "Invalid QualifierID found parsing CertifcatePolicies! PolicyQualifier ID must be one of: " +
							PolicyQualifierId.id_qt_cps + " or " + PolicyQualifierId.id_qt_unotice + "; found " + qualifierIdStr);
				}
				
				PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(qualifierId, qualifier);
				policyQualsArray.add(policyQualifierInfo);
			}
			
			PolicyInformation policyInformation = new PolicyInformation(policyIdentifier, new DERSequence(policyQualsArray));
			policyInfoArray[policyInfoArray_idx++] = policyInformation;
		}
		
		CertificatePolicies certPolicies = new CertificatePolicies(policyInfoArray);
		return certPolicies;
	}


	/**
	 * Create and return a TbbSecurityAssertions ASN1 object given the JAXB representation
	 * 
	 *    TBBSecurityAssertions ASN.1 structure.
	 *    
	 *    TBBSecurityAssertions ::= SEQUENCE {
	 *      version                Version DEFAULT v1,
	 *      ccInfo                 [0] IMPLICIT CommonCriteriaMeasures OPTIONAL,
	 *      fipsLevel              [1] IMPLICIT FIPSLevel OPTIONAL,
	 *      rtmType                [2] IMPLICIT MeasurementRootType OPTIONAL,
	 *      iso9000Certified       BOOLEAN DEFAULT FALSE,
	 *      iso9000Uri             IA5STRING OPTIONAL }
	 *
	 *    Version ::= INTEGER { v1(0) }
	 *     
	 *    CommonCriteriaMeasures ::= SEQUENCE {
	 *      version          IA5STRING, -- '2.2' or '3.0'; future syntax defined by CC
	 *      assurancelevel   EvaluationAssuranceLevel,
	 *      evaluationStatus EvaluationStatus,
	 *      plus             BOOLEAN DEFAULT FALSE,
	 *      strengthOfFunction [0] IMPLICIT StrengthOfFunction OPTIONAL,
	 *      profileOid         [1] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
	 *      profileUri         [2] IMPLICIT URIReference OPTIONAL,
	 *      targetOid          [3] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
	 *      targetUri          [4] IMPLICIT URIReference OPTIONAL }
   	 *   
	 *    EvaluationAssuranceLevel ::= ENUMERATED {
	 *      level1 (1),
	 *      level2 (2),
	 *      level3 (3),
	 *      level4 (4),
	 *      level5 (5),
	 *      level6 (6),
	 *      level7 (7) }
	 *      
	 *    EvaluationStatus ::= ENUMERATED {
	 *      designedToMeet (0),
	 *      evaluationInProgress (1),
	 *      evaluationCompleted (2) }
	 *      
	 *    StrengthOfFunction ::= ENUMERATED {
	 *      basic (0),
	 *      medium (1),
	 *      high (2) }
	 *   
	 *    -- Reference to external document containing information relevant to this subject. 
	 *    -- The hashAlgorithm and hashValue MUST both exist in each reference if either 
	 *    -- appear at all.
	 *    URIReference ::= SEQUENCE {
	 *      uniformResourceIdentifier IA5String,
	 *      hashAlgorithm             AlgorithmIdentifier OPTIONAL,
	 *      hashValue                 BIT STRING OPTIONAL }
   	 *      
	 *    FIPSLevel ::= SEQUENCE {
	 *      version IA5STRING, -- "140-1" or "140-2"
	 *      level SecurityLevel,
	 *      plus BOOLEAN DEFAULT FALSE }
   	 *      
	 *    SecurityLevel ::= ENUMERATED {
	 *      level1 (1),
	 *      level2 (2),
	 *      level3 (3),
	 *      level4 (4) }
   	 *      
	 *    MeasurementRootType ::= ENUMERATED {
	 *      static  (0),
	 *      dynamic (1),
	 *      nonHost (2) }
   	 *   
	 * @param platformCertificateData a JAXB representation of a PlatfromCertificate
	 * 
	 * @return an TbbSecurityAssertions object 
	 *         or NULL if no Security Assertions information is found in the input structure
	 */
	private TbbSecurityAssertions extract_TbbSecurityAssertions(PlatformCertificateData platformCertificateData)
	{
		// first get the information needed to build a TBB Security Assertions Object from the input structure
		Integer version = platformCertificateData.getPlatformAssertionsVersion();

		com.trustiphi.asn1.CommonCriteriaMeasures ccInfo = null;
		
		XmlCommonCriteriaMeasures in_CcInfo = platformCertificateData.getPlatformAssertionsCCInfo();
		if(in_CcInfo != null)
		{
			// initialize the ccInfo structure using the values in the input ccInfo
			ccInfo = new com.trustiphi.asn1.CommonCriteriaMeasures();
			
			if(in_CcInfo.getVersion() != null)
			{
				String in_ccInfo_Version = in_CcInfo.getVersion(); 
				ccInfo.setVersion(new DERIA5String(in_ccInfo_Version));
			}
			else {
				ccInfo.setVersion(new DERIA5String(""));
			}
			
			if(in_CcInfo.getAssurancelevel() != null)
			{
				Integer in_ccInfo_assuranceLevel = in_CcInfo.getAssurancelevel(); 
				ccInfo.setAssurancelevel(in_ccInfo_assuranceLevel);
			}
			
			if(in_CcInfo.getEvaluationStatus() != null)
			{
				Integer in_ccInfo_evalStatus = in_CcInfo.getEvaluationStatus();
				ccInfo.setEvaluationStatus(in_ccInfo_evalStatus);
			}

			if(in_CcInfo.isPlus() != null)
			{
				Boolean in_ccInfo_plus = in_CcInfo.isPlus();
				ccInfo.setPlus(in_ccInfo_plus);;
			}
			
			if(in_CcInfo.getStrengthOfFunction() != null)
			{
				Integer in_ccInfo_strengthOfFunc = in_CcInfo.getStrengthOfFunction();
				ccInfo.setStrengthOfFunction(in_ccInfo_strengthOfFunc);
			}

			boolean hasProfileUri = false;
			if(in_CcInfo.getProfileUri() != null)
			{
				if(in_CcInfo.getProfileOid() != null)
				{
					XmlURIReference in_ccInfo_profileUri =
							in_CcInfo.getProfileUri();
					
					String uriRef_uriRefId = in_ccInfo_profileUri.getUniformResourceIdentifier();
					String uriRef_hashAlg = in_ccInfo_profileUri.getHashAlgorithm();
					byte[] uriRef_hashVal = in_ccInfo_profileUri.getHashValue();
					
					if(uriRef_uriRefId != null || uriRef_hashAlg != null || uriRef_hashVal != null)
					{
						com.trustiphi.asn1.URIReference profileUri = new com.trustiphi.asn1.URIReference();
						if(uriRef_uriRefId != null)
						{
							profileUri.setUniformResourceIdentifier(new DERIA5String(uriRef_uriRefId));
						}
						else {
							profileUri.setUniformResourceIdentifier(new DERIA5String(""));
							// This is a required field of uriRef
							LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found profileUri but missing uniformResourceIdentifier! " +
									"Setting profileUri.uniformResourceIdentifier to the empty string!");
						}

						if(uriRef_hashAlg != null)
						{
							profileUri.setHashAlgorithm(new AlgorithmIdentifier(new ASN1ObjectIdentifier(uriRef_hashAlg)));
							if(uriRef_hashVal == null)
							{
								// Must have both algorithm and value or neither - just warn for now...
								LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found profileUri.hashAlg but missing profileUri.hashVal - must have both or neither! ");
							}
						}
						
						if(uriRef_hashVal != null)
						{
							profileUri.setHashValue(new DERBitString(uriRef_hashVal));
							if(uriRef_hashAlg == null)
							{
								// Must have both algorithm and value or neither - just warn for now...
								LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found profileUri.hashVal but missing profileUri.hashAlg - must have both or neither! ");
							}
						}
						
						ccInfo.setProfileUri(profileUri);
						hasProfileUri = true;
					}
				}
				else {
					// Must have both target OID and URI or neither - skip (to avoid exceptions later)
					// and output an error
					LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found profileUri but missing profileOid - Must have both or neither! " +
							"Skipping profileUri!");
				}
			}
			
			if(in_CcInfo.getProfileOid() != null)
			{
				if(hasProfileUri)
				{
					String in_ccInfo_profileOid = in_CcInfo.getProfileOid();
					ccInfo.setProfileOid(new ASN1ObjectIdentifier(in_ccInfo_profileOid));
				}
				else {
					// Must have both target OID and URI or neither - skip (to avoid exceptions later)
					// and output an error
					LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found profileOid but missing profileUri - Must have both or neither! " +
							"Skipping profileOid!");
				}
			}
			
			boolean hasTargetUri = false;			
			if(in_CcInfo.getTargetUri() != null)
			{
				if(in_CcInfo.getTargetOid() != null)
				{
					XmlURIReference in_ccInfo_targetUri =
							in_CcInfo.getTargetUri();
					
					String uriRef_uriRefId = in_ccInfo_targetUri.getUniformResourceIdentifier();
					String uriRef_hashAlg = in_ccInfo_targetUri.getHashAlgorithm();
					byte[] uriRef_hashVal = in_ccInfo_targetUri.getHashValue();
					
					if(uriRef_uriRefId != null || uriRef_hashAlg != null || uriRef_hashVal != null)
					{
						com.trustiphi.asn1.URIReference targetUri = new com.trustiphi.asn1.URIReference();
						if(uriRef_uriRefId != null)
						{
							targetUri.setUniformResourceIdentifier(new DERIA5String(uriRef_uriRefId));
						}
						else {
							targetUri.setUniformResourceIdentifier(new DERIA5String(""));
							// This is a required field of uriRef
							LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found targetUri but missing uniformResourceIdentifier! " +
									"Setting targetUri.uniformResourceIdentifier to the empty string!");
						}
						
						if(uriRef_hashAlg != null)
						{
							targetUri.setHashAlgorithm(new AlgorithmIdentifier(new ASN1ObjectIdentifier(uriRef_hashAlg)));
							if(uriRef_hashVal == null)
							{
								// Must have both algorithm and value or neither - just warn for now...
								LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found targetUri.hashAlg but missing targetUri.hashVal - must have both or neither! ");
							}
						}
						
						if(uriRef_hashVal != null)
						{
							targetUri.setHashValue(new DERBitString(uriRef_hashVal));
							if(uriRef_hashAlg == null)
							{
								// Must have both algorithm and value or neither - just warn for now...
								LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found targetUri.hashVal but missing targetUri.hashAlg - must have both or neither! ");
							}
						}
						
						ccInfo.setTargetUri(targetUri);				
						hasTargetUri = true;
					}
				}
				else {
					// Must have both target OID and URI or neither - skip (to avoid exceptions later)
					// and output an error
					LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found TargetURI but missing TargetOid - Must have both or neither! " +
							"Skipping TargetURI!");
				}
			}
			
			if(in_CcInfo.getTargetOid() != null)
			{
				if(hasTargetUri)
				{
					String in_ccInfo_targetOid = in_CcInfo.getTargetOid();
					ccInfo.setTargetOid(new ASN1ObjectIdentifier(in_ccInfo_targetOid));
				}
				else {
					// Must have both target OID and URI or neither - skip (to avoid exceptions later)
					// and output an error
					LOG_ERRROR("extract_TbbSecurityAssertions", "Invalid CommonCriteriaMeasures encountered parsing TbbSecurityAssertions! Found targetOid but missing targetUri - Must have both or neither! " +
							"Skipping targetOid!");
				}
			}
		}

		com.trustiphi.asn1.FIPSLevel fipsLevel = null;
		if(platformCertificateData.getPlatformAssertionsFipsLevelVersion() != null || 
				platformCertificateData.getPlatformAssertionsFipsLevel() != null ||
				platformCertificateData.isPlatformAssertionsFipsLevelPlus() != null )
		{
			fipsLevel = 
					new com.trustiphi.asn1.FIPSLevel(platformCertificateData.getPlatformAssertionsFipsLevelVersion(),
							                         platformCertificateData.getPlatformAssertionsFipsLevel(),
							                         platformCertificateData.isPlatformAssertionsFipsLevelPlus());
		}

		Integer rtmType = platformCertificateData.getPlatformAssertionsRtmType();
		Boolean iso9000Certified = platformCertificateData.isPlatformAssertionsIso9000Certified();
		String iso9000Uri = platformCertificateData.getPlatformAssertionsIso9000Uri();
		
		if(version == null && ccInfo == null && fipsLevel == null && 
			rtmType==null && iso9000Certified==null && iso9000Uri==null)
		{
			// no TbbSecurityAssertions found - return null
			return null;
		}
		
		TbbSecurityAssertions tbbSecurityAssertions  = 
				new TbbSecurityAssertions(version, ccInfo, fipsLevel, rtmType, iso9000Certified, iso9000Uri);
		
		
		return tbbSecurityAssertions;
	}
	

	/***
	 * Extract the tbb-SecurityAssertions information from X509AttributeCertificateHolder
	 * and return a TbbSecurityAssertions initialized with that information.
	 * 
	 * If the X509AttributeCertificateHolder does not contain any PlatformSpecification fields return null.
	 * 
	 * @param platformCertificateData
	 * @return TcgPlatformSpecification initialized with that information, or null if no tcgPlatformSpecification fields found
	 */
	private TbbSecurityAssertions extract_TbbSecurityAssertions(X509AttributeCertificateHolder x509AttrCertHolder)
	{
		TbbSecurityAssertions retTbbSecurityAssertions = null;
		
		Attribute attributes[] = x509AttrCertHolder.getAttributes(OBJECT_IDENTIFIER_tcg_at_tbbSecurityAssertions);
		if(attributes.length > 0)
		{
			ASN1Set tbbSecurityAssertionsSet = attributes[0].getAttrValues();
			if(tbbSecurityAssertionsSet != null && tbbSecurityAssertionsSet.toArray().length > 0)
			{
				try {
					retTbbSecurityAssertions = new TbbSecurityAssertions(tbbSecurityAssertionsSet.toArray()[0]);
				} catch (IOException e) {
					LOG_ERRROR("extract_tcgPlatformSpecification", e.getMessage());
				}
			}
		}
		
		return retTbbSecurityAssertions;
	}
	
	/***
	 * Extract the AuthorityKeyIdentifier information from the PlatformCertificateData object
	 * and return an AuthorityKeyIdentifier initialized with that information.
	 * 
	 * If the platformCertificateData does not contain the AuthorityKeyIdentifier field return null.
	 *
	 *  The specification of an AuthorityKeyIdentifier is as follows,
	 *  BUT NOTE that in this implementation ONLY the keyIdentifier is included in the AuthorityKeyIdentifier
	 * 
	 * AuthorityKeyIdentifier ::= SEQUENCE {
	 *       keyIdentifier             [0] IMPLICIT KeyIdentifier           OPTIONAL,
	 *       authorityCertIssuer       [1] IMPLICIT GeneralNames            OPTIONAL,
	 *       authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL  }
	 *          
	 * KeyIdentifier ::= OCTET STRING 
	 * 
	 * 
	 * @param[in] platformCertificateData
	 * @return TcgPlatformSpecification initialized with that information, or null the AuthorityKeyIdentifier fields is not found
	 */
	private AuthorityKeyIdentifier extract_AuthorityKeyIdentifier(PlatformCertificateData platformCertificateData)
	{
		byte[]  key_identifier = platformCertificateData.getAuthorityKeyIdentifier();

		// no Platform SPecification to return so just return null
		if(key_identifier == null)
		{
			return null;
		}
		
		AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier(key_identifier);
		
		return authorityKeyIdentifier;
	}
	
	
	/***
	 * Extract the AuthorityInfoAccess information from the PlatformCertificateData object
	 * and return an AuthorityInfoAccess initialized with that information.
	 * 
	 * If the platformCertificateData does not contain the AuthorityInfoAccess fields return null.
	 *
	 *  The specification of an AuthorityInfoAccess is as follows,
	 *  
	 * 	AuthorityInfoAccessSyntax  ::=
	 * 	      SEQUENCE SIZE (1..MAX) OF AccessDescription
	 * 
	 * 	 AccessDescription  ::=  SEQUENCE {
	 * 	       accessMethod          OBJECT IDENTIFIER,
	 * 	       accessLocation        GeneralName  }
	 * 
	 * 
	 * @param[in] platformCertificateData
	 * @return TcgPlatformSpecification initialized with that information, or null the AuthorityKeyIdentifier fields is not found
	 */
	private AuthorityInformationAccess extract_AuthorityInformationAccess(PlatformCertificateData platformCertificateData)
	{
		String accessMethod = platformCertificateData.getAuthorityAccessMethod();
		XmlGeneralName xmlGeneralName = platformCertificateData.getAuthorityAccessLocation();
		GeneralName accessLocation=null;

		if(xmlGeneralName != null)
		{
			String name = xmlGeneralName.getName();
			if(name != null)
			{
				try {
					int tag = xmlGeneralName.getTag().ordinal();
					accessLocation = new GeneralName(tag, name);
				}
				catch(IllegalArgumentException x)
				{
					// shouldn't happen! For now, don't do anything - just skip it
					// TODO add logging
				}
				
			}
		}
		
		// no PAuthorityInformationAccess information found to return so just return null
		if(accessMethod == null || accessLocation == null)
		{
			return null;
		}
		
		AuthorityInformationAccess authorityInformationAccess = 
				new AuthorityInformationAccess(new ASN1ObjectIdentifier(accessMethod), accessLocation);
		
		return authorityInformationAccess;
	}
	
	
	/***
	 * Extract the platform information for the SubjectAltName extension from the PlatformCertificateData object
	 * and return a GeneralNames initialized with that information.
	 * 
	 * If the platformCertificateData does not contain any of the desired fields return null.
	 * 
	 * @param platformCertificateData
	 * @return GeneralNames initialized with that information, or null if no relevant fields found
	 */
	private GeneralNames extract_PlatformInformation(PlatformCertificateData platformCertificateData)
	{
		String platform_manufacturer_str = platformCertificateData.getPlatformManufacturerStr();
		String platform_model            = platformCertificateData.getPlatformModel();
		String platform_version          = platformCertificateData.getPlatformVersion();
		String platform_serial           = platformCertificateData.getPlatformSerial();
		List<String> platform_manufacturer_id  = platformCertificateData.getPlatformManufacturerId();

		// no platform information found to return so just return null
		if(platform_manufacturer_str == null &&
		   (platform_manufacturer_id == null || platform_manufacturer_id.isEmpty()) &&
		   platform_model == null && 
		   platform_version == null &&
		   platform_serial == null)
		{
			return null;
		}

		X500NameBuilder x500NameBuilder = new X500NameBuilder();
		if(platform_manufacturer_str != null)
		{
			x500NameBuilder.addRDN(TrustiPhiStyle.platformManufacturerStr, platform_manufacturer_str);
		}
		if(platform_manufacturer_id != null && !platform_manufacturer_id.isEmpty())
		{
			ManufacturerId manufacturerId = new ManufacturerId();
			for(String manufacturer_ident: platform_manufacturer_id)
			{
				manufacturerId.add(manufacturer_ident);
			}
			x500NameBuilder.addRDN(TrustiPhiStyle.platformManufacturerId, manufacturerId);
		}
		if(platform_model != null)
		{
			x500NameBuilder.addRDN(TrustiPhiStyle.platformModel, platform_model);
		}
		if(platform_version != null)
		{
			x500NameBuilder.addRDN(TrustiPhiStyle.platformVersion, platform_version);
		}
		if(platform_serial != null)
		{
			x500NameBuilder.addRDN(TrustiPhiStyle.platformSerial, platform_serial);
		}
		GeneralName generalName = new GeneralName(GeneralName.directoryName, x500NameBuilder.build());
		GeneralNames subjectAltName = new GeneralNames(generalName);
		
		return subjectAltName;
	}
	
	/**
	 * Create and return a CRLDistPoint ASN1 object given the JAXB representation
	 * 
	 * The following is the defined format of a CertficatePolicies structure:
	 * 
	 * cRLDistributionPoints EXTENSION ::= {
	 *		SYNTAX CRLDistPointSyntax
	 *		IDENTIFIED BY id-ce-cRLDistributionPoints
	 *	}
	 *	
	 *	CRLDistPointSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	 *	
	 *	DistributionPoint ::= SEQUENCE {
	 *		distributionPoint [0] DistributionPointName OPTIONAL,
	 *		reasons		  [1] ReasonFlags OPTIONAL,
	 *		cRLIssuer	  [2] GeneralNames OPTIONAL
	 *	}
	 *	
	 *	DistributionPointName ::= CHOICE {
	 *		fullname	[0] GeneralNames,
	 *		nameRelativeToCRLIssuer [1] RelativeDistinguishedName
	 *	}
	 *	
	 *	ReasonFlags ::= BIT STRING {
	 *		unused(0),
	 *		keyCompromise(1),
	 *		cACompromise(2)
	 *		affiliationChanged(3),
	 *		superseded(4),
	 *		cessationOfOperation(5),
	 *		certificateHold(6)
	 *	}
	 *
	 *  RelativeDistinguishedName ::= SET SIZE (1..MAX) OF
     *       AttributeTypeAndValue
     *
     *   AttributeTypeAndValue ::= SEQUENCE {
     *       type  AttributeType,
     *       value AttributeValue 
     *   }   
	 *   
	 * @param platformCertificateData a JAXB representation of a PlatfromCertificate
	 * 
	 * @return an ASN1 representation of a CRLDistPoint 
	 *         or NULL if CRLDistPoint id not found in the input structure
	 */
	private CRLDistPoint extract_CRLDistPoint(PlatformCertificateData platformCertificateData)
	{
	    if (platformCertificateData.getCRLDistributionPoints() == null || platformCertificateData.getCRLDistributionPoints().size() == 0) {
	        return null;
	    }
	    
	    DistributionPoint[] pointInfoArray = new DistributionPoint[platformCertificateData.getCRLDistributionPoints().size()];
        
        int pointInfoArray_idx=0;
        for(XmlCRLDistributionPoints cRLdistributionPoints: platformCertificateData.getCRLDistributionPoints())
        {         
            DistributionPointName distributionPoint = null;
            ReasonFlags reasons = null;
            GeneralNames cRLIssuer = null;
            
            if (cRLdistributionPoints.getDistributionPoint() != null)
            {
                int tag = 0;
                List<XmlGeneralName> distributionPointInfo = null;
                
                // choice for distributinoPointName: either fullName or nameRelativeToCRLIssuer
                if (cRLdistributionPoints.getDistributionPoint().getFullname().size() > 0) 
                {
                    // fullName
                    tag = 0;
                    distributionPointInfo = cRLdistributionPoints.getDistributionPoint().getFullname();
                }
                else if (cRLdistributionPoints.getDistributionPoint().getNameRelativeToCRLIssuer().size() > 0)
                {
                    // nameRelativeToCRLIssuer
                    tag = 1;
                    distributionPointInfo = cRLdistributionPoints.getDistributionPoint().getNameRelativeToCRLIssuer();
                }
                if (distributionPointInfo.size() > 0)
                {
                    GeneralName[] generalName_array = new GeneralName[distributionPointInfo.size()];
                    
                    for (int i = 0; i <distributionPointInfo.size(); i++)
                    {
                        generalName_array[i] = new GeneralName(distributionPointInfo.get(i).getTag().ordinal(),
                                distributionPointInfo.get(i).getName());
                    }
                    distributionPoint = new DistributionPointName(tag, new GeneralNames(generalName_array));
                }              
            }
            
            if (cRLdistributionPoints.getReasons() != null)
            {
                // reasonString is a string of 1s and 0s and should be converted to byte[]
                String reasonString = cRLdistributionPoints.getReasons();
                if (reasonString != null) 
                {
                    reasons = new ReasonFlags(new DERBitString(new BigInteger(reasonString, 2).toByteArray()));
                }
            }

            if (cRLdistributionPoints.getCRLIssuer() != null)
            {
                XmlGeneralName cRLIssuerInfo = cRLdistributionPoints.getCRLIssuer();
                cRLIssuer = new GeneralNames(new GeneralName(cRLIssuerInfo.getTag().ordinal(), cRLIssuerInfo.getName())); 
            }
          
            DistributionPoint pointInfo = new DistributionPoint(distributionPoint, reasons, cRLIssuer);            
            pointInfoArray[pointInfoArray_idx++] = pointInfo;
        }
             
        CRLDistPoint cRLDistpoint = new CRLDistPoint(pointInfoArray);
        return cRLDistpoint;    
	}
	
    /***
     * Extract the CRLDistPoint information from X509AttributeCertificateHolder
     * and return a CRLDistPoint initialized with that information.
     * 
     * If the X509AttributeCertificateHolder does not contain any CRLDistPoint fields return null.
     * 
     * @param x509AttrCertHolder
     * @return CRLDistPoint initialized with that information, or null if no CRLDistPoint fields found
     */
    private CRLDistPoint extract_CRLDistPoint(X509AttributeCertificateHolder x509AttrCertHolder)
    {
        CRLDistPoint retCRLDistPoint = null;
        
        if (x509AttrCertHolder.getExtension(OBJECT_IDENTIFIER_id_ce_CRLDistributionPoints) == null)
        {
            return null;
        }
        
        ASN1Encodable cRLDistPointEncodable = x509AttrCertHolder.getExtension(OBJECT_IDENTIFIER_id_ce_CRLDistributionPoints)
                .getParsedValue();
        if (cRLDistPointEncodable instanceof ASN1Sequence)
        {
            ASN1Encodable[] cRLDistPointEncodable_array = ((ASN1Sequence) cRLDistPointEncodable).toArray();
            
            if (cRLDistPointEncodable_array.length > 0)
            {
                DistributionPoint[] distributinPoint = new DistributionPoint[cRLDistPointEncodable_array.length];
                
                for (int i = 0; i < cRLDistPointEncodable_array.length; i++)
                {
                    if (cRLDistPointEncodable_array[i] instanceof ASN1Sequence)
                    {
                        distributinPoint[i] = new DistributionPoint((ASN1Sequence) cRLDistPointEncodable_array[i]);
                    }
                    else
                    {
                        // unexpected type
                        LOG_ERRROR("extract_CRLDistPoint",
                                "Unexpected ASN1 formatting while parsing DistributionPoint. Expected ASN1Seqeunce; Found " 
                                        + cRLDistPointEncodable_array[i].getClass().toString());
                    }
                }
                
                retCRLDistPoint = new CRLDistPoint(distributinPoint);
            }  
        }
        else
        {
            // unexpected type
            LOG_ERRROR("extract_CRLDistPoint",
                    "Unexpected ASN1 formatting while parsing CRLDistributionPoints. Expected ASN1Seqeunce; Found " 
                            + cRLDistPointEncodable.getClass().toString());
        }
        
        return retCRLDistPoint;
    }
	
	/***
	 * Set the JAXB fields of found in the tcgPlatformSpecification object
	 * 
	 * If the tcgplatformCertificateData is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_TcgPlatformSpecificationFields(PlatformCertificateData platformCertificateData)
	{
		if(tcgPlatformSpecification == null)
		{
			return;
		}
		
		platformCertificateData.setPlatformClass(tcgPlatformSpecification.getPlatformClass());
		platformCertificateData.setMajorVersion(tcgPlatformSpecification.getMajorVersion());
		platformCertificateData.setMinorVersion(tcgPlatformSpecification.getMinorVersion());
		platformCertificateData.setRevision(tcgPlatformSpecification.getRevision());
	}
	
	/***
     * Set the JAXB fields of found in the tcgCredentialSpecification object
     * 
     * If the tcgplatformCertificateData is null don't change the input PlatformCertificateData.
     * 
     * @param[out] platformCertificateData
     */
    private void set_TcgCredentialSpecificationFields(PlatformCertificateData platformCertificateData)
    {
        if(tcgCredentialSpecification == null)
        {
            return;
        }
        
        platformCertificateData.setTcgCredentialSpecificationMajorVersion(tcgCredentialSpecification.getMajorVersion());
        platformCertificateData.setTcgCredentialSpecificationMinorVersion(tcgCredentialSpecification.getMinorVersion());
        platformCertificateData.setTcgCredentialSpecificationRevision(tcgCredentialSpecification.getRevision());
    }

	
	/***
	 * Set the JAXB fields of found in the TbbSecurityAssertions object
	 * 
	 * If the tbbSecurityAssertions is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_TbbSecurityAssertionsFields(PlatformCertificateData platformCertificateData)
	{
		if(tbbSecurityAssertions == null)
		{
			return;
		}
		
		// first set the information needed to build a TBB Security Assertions Object from the input structure
		
		platformCertificateData.setPlatformAssertionsVersion(tbbSecurityAssertions.getVersion());
		
		CommonCriteriaMeasures ccInfo = tbbSecurityAssertions.getCcInfo();
		if(ccInfo != null)
		{
			XmlCommonCriteriaMeasures jaxbCcInfo = new XmlCommonCriteriaMeasures();
			jaxbCcInfo.setVersion(ccInfo.getVersion().getString());
			jaxbCcInfo.setAssurancelevel(ccInfo.getAssurancelevel());
			jaxbCcInfo.setEvaluationStatus(ccInfo.getEvaluationStatus());
			jaxbCcInfo.setPlus(ccInfo.getPlus());
			jaxbCcInfo.setStrengthOfFunction(ccInfo.getStrengthOfFunction());
			if(ccInfo.getProfileOid() != null)
			{
				jaxbCcInfo.setProfileOid(ccInfo.getProfileOid().getId());
			}
			if(ccInfo.getProfileUri() != null)
			{
				XmlURIReference xmlProfileUri = new XmlURIReference();

				if(ccInfo.getProfileUri().getUniformResourceIdentifier() != null)
				{
					xmlProfileUri.setUniformResourceIdentifier(
						ccInfo.getProfileUri().getUniformResourceIdentifier().getString());
				}
				if(ccInfo.getProfileUri().getHashAlgorithm() != null)
				{
					xmlProfileUri.setHashAlgorithm(ccInfo.getProfileUri().getHashAlgorithm().getAlgorithm().getId());
				}
				if(ccInfo.getProfileUri().getHashValue() != null)
				{
					xmlProfileUri.setHashValue(ccInfo.getProfileUri().getHashValue().getBytes());
				}
				
				jaxbCcInfo.setProfileUri(xmlProfileUri);
			}
			if(ccInfo.getTargetOid() != null)
			{
				jaxbCcInfo.setTargetOid(ccInfo.getTargetOid().getId());
			}
			if(ccInfo.getTargetUri() != null)
			{
				XmlURIReference xmlTargetUri = new XmlURIReference();

				if(ccInfo.getTargetUri().getUniformResourceIdentifier() != null)
				{
					xmlTargetUri.setUniformResourceIdentifier(
						ccInfo.getTargetUri().getUniformResourceIdentifier().getString());
				}
				if(ccInfo.getTargetUri().getHashAlgorithm() != null)
				{
					xmlTargetUri.setHashAlgorithm(ccInfo.getTargetUri().getHashAlgorithm().getAlgorithm().getId());
				}
				if(ccInfo.getTargetUri().getHashValue() != null)
				{
					xmlTargetUri.setHashValue(ccInfo.getTargetUri().getHashValue().getBytes());
				}
				
				jaxbCcInfo.setTargetUri(xmlTargetUri);
			}
			platformCertificateData.setPlatformAssertionsCCInfo(jaxbCcInfo);
		}
		

		FIPSLevel fipsLevel = tbbSecurityAssertions.getFipsLevel();
		if(fipsLevel != null)
		{
			platformCertificateData.setPlatformAssertionsFipsLevelVersion(fipsLevel.getVersion()); 
			platformCertificateData.setPlatformAssertionsFipsLevel(fipsLevel.getLevel());
			platformCertificateData.setPlatformAssertionsFipsLevelPlus(fipsLevel.getPlus());
		}
		
		platformCertificateData.setPlatformAssertionsRtmType(tbbSecurityAssertions.getRtmType());
		platformCertificateData.setPlatformAssertionsIso9000Certified(tbbSecurityAssertions.getIso9000Certified());
		platformCertificateData.setPlatformAssertionsIso9000Uri(tbbSecurityAssertions.getIso9000Uri());
	}
	
	/***
     * Set the JAXB fields of found in the PlatformConfigUri object
     * 
     * If the platformConfigUri is null don't change the input PlatformCertificateData.
     * 
     * @param[out] platformCertificateData
     */
    private void set_PlatformConfigUri(PlatformCertificateData platformCertificateData)
    {
        if(platformConfigUri == null)
        {
            return;
        }
        
        XmlURIReference platformConfigUriInfo = new XmlURIReference();
        
        if (platformConfigUri.getHashAlgorithm() != null)
        {
            platformConfigUriInfo.setHashAlgorithm(platformConfigUri.getHashAlgorithm().getAlgorithm().getId());
        }
        if (platformConfigUri.getHashValue() != null)
        {
            platformConfigUriInfo.setHashValue(platformConfigUri.getHashValue().getBytes());
        }
        if (platformConfigUri.getUniformResourceIdentifier() != null)
        {
            platformConfigUriInfo.setUniformResourceIdentifier(
                    platformConfigUri.getUniformResourceIdentifier().getString());
        }
    
        platformCertificateData.setPlatformConfigUri(platformConfigUriInfo);
    }
    
    /***
     * Set the JAXB fields of found in the PlatformConfiguration object
     * 
     * If th ePlatformConfiguration is null don't change the input PlatformCertificateData.
     * 
     * @param[out] platformCertificateData
     */
    private void set_PlatformConfiguration(PlatformCertificateData platformCertificateData)
    {
        if(platformConfiguration == null)
        {
            return;
        }
        
        // ComponentIdentifier
        ComponentIdentifier[] componentIdentifier = platformConfiguration.getComponentIdentifier();
        List<XmlComponentIdentifier> componentIdentifierInfo = platformCertificateData.getComponentIdentifier();
        if (componentIdentifier != null)
        {
            for(ComponentIdentifier componentIdentifierElement : componentIdentifier)
            {
                XmlComponentIdentifier xmlComponentIdentifier = new XmlComponentIdentifier();
                
                if (componentIdentifierElement != null)
                {
                    if (componentIdentifierElement.getComponentManufacturer() != null)
                    {
                        xmlComponentIdentifier.setComponentManufacturer(componentIdentifierElement.getComponentManufacturer());
                    }
                    if (componentIdentifierElement.getComponentModel() != null)
                    {
                        xmlComponentIdentifier.setComponentModel(componentIdentifierElement.getComponentModel());
                    }              
                    if (componentIdentifierElement.getComponentSerial() != null)
                    {
                        xmlComponentIdentifier.setComponentSerial(componentIdentifierElement.getComponentSerial());
                    }
                    if (componentIdentifierElement.getComponentRevision() != null)
                    {
                        xmlComponentIdentifier.setComponentRevision(componentIdentifierElement.getComponentRevision());
                    }
                    if (componentIdentifierElement.getComponentManufacturerId() != null)
                    {
                        xmlComponentIdentifier.setComponentManufacturerId(componentIdentifierElement
                                .getComponentManufacturerId().getId());
                    }
                    if (componentIdentifierElement.getFieldReplaceable() != null)
                    {
                        xmlComponentIdentifier.setFieldReplaceable(componentIdentifierElement.getFieldReplaceable());
                    }
                    if (componentIdentifierElement.getComponentAddress() != null)
                    {
                        ComponentAddress[] componentAddress = componentIdentifierElement.getComponentAddress();
                        List<XmlComponentAddress> componentAddressInfo = xmlComponentIdentifier.getComponentAddress();
                        
                        for (ComponentAddress componentAddressElement : componentAddress)
                        {
                            XmlComponentAddress xmlComponentAddress = new XmlComponentAddress();
                            
                            if (componentAddressElement != null)
                            {
                                if (componentAddressElement.getAddressType() != null)
                                {
                                    xmlComponentAddress.setAddressType(componentAddressElement.getAddressType().getId());
                                }
                                if (componentAddressElement.getAddressValue() != null)
                                {
                                    xmlComponentAddress.setAddressValue(componentAddressElement.getAddressValue());
                                }                  
                            }
                            componentAddressInfo.add(xmlComponentAddress);
                        }
                    }                    
                }
                componentIdentifierInfo.add(xmlComponentIdentifier);
            }
        }        
        
        // PlatformProperties
        Properties[] platformProperties = platformConfiguration.getPlatformProperties();
        List<XmlProperties> platformPropertiesInfo = platformCertificateData.getPlatformProperties();
        
        if (platformProperties != null)
        {
            for(Properties propertiesElement : platformProperties)
            {
                XmlProperties xmlProperties = new XmlProperties();
                
                if (propertiesElement != null)
                {
                    if (propertiesElement.getPropertyName() != null)
                    {
                        xmlProperties.setPropertyName(propertiesElement.getPropertyName());
                    }
                    if (propertiesElement.getPropertyValue() != null)
                    {
                        xmlProperties.setPropertyValue(propertiesElement.getPropertyValue());
                    }                
                }
                platformPropertiesInfo.add(xmlProperties);
            }
        }
        
        // PlatformPropertiesUri
        URIReference platformPropertiesUri = platformConfiguration.getPlatformPropertiesUri();
        
        if (platformPropertiesUri != null)
        {
            XmlURIReference platformPropertiesUriInfo = new XmlURIReference();
            
            if (platformPropertiesUri.getHashAlgorithm() != null)
            {
                platformPropertiesUriInfo.setHashAlgorithm(platformPropertiesUri
                        .getHashAlgorithm().getAlgorithm().getId());
            }
            if (platformPropertiesUri.getHashValue() != null)
            {
                platformPropertiesUriInfo.setHashValue(platformPropertiesUri.getHashValue().getBytes());
            }
            if (platformPropertiesUri.getUniformResourceIdentifier() != null)
            {
                platformPropertiesUriInfo.setUniformResourceIdentifier(platformPropertiesUri
                        .getUniformResourceIdentifier().getString());
            }
            
            platformCertificateData.setPlatformPropertiesUri(platformPropertiesUriInfo);  
        }      
    }

	/***
	 * Set the JAXB fields of found in the CertificatePolicies object
	 * 
	 * If the CertificatePolicies is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_CertificatePoliciesFields(PlatformCertificateData platformCertificateData)
	{
		if(this.certificate_policies == null)
		{
			return;
		}
		
		List<XmlCertificatePolicies> jaxbCertificatePolicies = new ArrayList<XmlCertificatePolicies>();
		PolicyInformation[] policyInfoArray = this.certificate_policies.getPolicyInformation();
		

		if(policyInfoArray != null)
		{
			for(PolicyInformation policyInfo: policyInfoArray)
			{
				XmlCertificatePolicies xmlCertPolicies = new XmlCertificatePolicies();

				
				ASN1ObjectIdentifier policyId = policyInfo.getPolicyIdentifier();
				if(policyId != null)
				{
					xmlCertPolicies.setPolicyIdentifier(policyId.getId());

					if(policyInfo.getPolicyQualifiers() != null)
					{
						ASN1Encodable[] policyQualsEncodable = policyInfo.getPolicyQualifiers().toArray();
						for(int i=0; i < policyQualsEncodable.length; i++)
						{
							PolicyQualifierInfo policyQualifierInfo = PolicyQualifierInfo.getInstance(policyQualsEncodable[i]);
							if(policyQualifierInfo != null)
							{
								XmlPolicyQualifier xmlPolicyQualifier = new XmlPolicyQualifier();
								ASN1ObjectIdentifier qualifierId = policyQualifierInfo.getPolicyQualifierId();
								if(qualifierId != null)
								{
									xmlPolicyQualifier.setPolicyQualifierId(qualifierId.getId());
									if(PolicyQualifierId.id_qt_cps.equals(qualifierId))
									{
										xmlPolicyQualifier.setQualifier(((DERIA5String)policyQualifierInfo.getQualifier()).getString());
									} 
									else if(PolicyQualifierId.id_qt_unotice.equals(qualifierId)) 
									{
										UserNotice userNotice = UserNotice.getInstance(policyQualifierInfo.getQualifier());
										if(userNotice.getExplicitText() != null)
										{
											xmlPolicyQualifier.setQualifier(userNotice.getExplicitText().getString());
										}
										else {
											// TODO Log error notice
											xmlPolicyQualifier.setQualifier("");
										}
									} 
									else {
										continue;
									}
					
									xmlCertPolicies.getPolicyQualifier().add(xmlPolicyQualifier);
								}
							}
						}
					}
					
					jaxbCertificatePolicies.add(xmlCertPolicies);
				}
			}
		}
		
		platformCertificateData.getCertificatePolicies().addAll(jaxbCertificatePolicies);
		
	}


	/***
	 * Set the JAXB fields of found in the AuthorityInformationAccess object
	 * 
	 * If the AuthorityInformationAccess object contains more than one AccessDescription,
	 * the first one is used to set the AuthorityAccessMethod and AuthorityAccessLocation
	 * fields of the PlatformCertificateData object.
	 * 
	 * If the AuthorityInformationAccess is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_AuthorityInformationAccess(PlatformCertificateData platformCertificateData)
	{
		if(this.authorityInformationAccess == null)
		{
			return;
		}
		AccessDescription[] accessDescriptions = this.authorityInformationAccess.getAccessDescriptions();
		
		if(accessDescriptions != null && accessDescriptions.length > 0)
		{
			AccessDescription accessDescription = accessDescriptions[0];
			if(accessDescription != null)
			{
				if(accessDescription.getAccessMethod() != null)
				{
					platformCertificateData.setAuthorityAccessMethod(accessDescription.getAccessMethod().getId());
				}
				
				if(accessDescription.getAccessLocation() != null)
				{
					XmlGeneralName accessLocGenName = new XmlGeneralName();
					if(accessDescription.getAccessLocation().getName() != null)
					{
						accessLocGenName.setName(accessDescription.getAccessLocation().getName().toString());
						XmlGeneralNameTag tag = 
								XmlGeneralNameTag.fromValue(
										ParsingUtils.getGeneralNameTagStringValue(accessDescription.getAccessLocation().getTagNo()));
						accessLocGenName.setTag(tag);
						
						platformCertificateData.setAuthorityAccessLocation(accessLocGenName);
					}
				}
			}
		}
	}
	
	
	/***
	 * Set the JAXB fields of found in the AuthorityKeyIdentifier object
	 * 
	 *  NOTE that in this implementation ONLY the keyIdentifier is included in the AuthorityKeyIdentifier
	 * 
	 * If the AuthorityKeyIdentifier is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_AuthorityKeyIdentifier(PlatformCertificateData platformCertificateData)
	{
		if(this.authorityKeyIdentifier == null)
		{
			return;
		}
		
		byte[] keyIdentifier = this.authorityKeyIdentifier.getKeyIdentifier();
		
		if(keyIdentifier != null)
		{
			platformCertificateData.setAuthorityKeyIdentifier(keyIdentifier);
		}
	}
	
	
	/***
	 * Set the JAXB fields of found in the SubjectAlternativeName (PlatformInformation GeneralNames) object
	 * 
	 * If the SubjectAlternativeName is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_PlatformInformation(PlatformCertificateData platformCertificateData)
	{
		if(this.subjectAltName == null)
		{
			return;
		}
		
		GeneralName[] generalNames = this.subjectAltName.getNames();
		
		if(generalNames != null && generalNames.length > 0)
		{
			GeneralName name = generalNames[0];
			if(name != null)
			{
				if(name.getTagNo() == GeneralName.directoryName && name.getName() instanceof X500Name)
				{
					X500Name x500Name = (X500Name) name.getName();
					RDN[] rdns = x500Name.getRDNs(TrustiPhiStyle.platformManufacturerStr);
					if(rdns != null && rdns.length > 0 && rdns[0].getFirst() != null)
					{
						platformCertificateData.setPlatformManufacturerStr(rdns[0].getFirst().getValue().toString());
					}
					rdns = x500Name.getRDNs(TrustiPhiStyle.platformManufacturerId);
					if(rdns != null && rdns.length > 0 && rdns[0].getFirst() != null)
					{
						ManufacturerId manufacturerId;
						try {
							manufacturerId = new ManufacturerId(rdns[0].getFirst().getValue());
							for(String manufacturerIdentifier: manufacturerId.getManufacturerIdList())
							{
								platformCertificateData.getPlatformManufacturerId().add(manufacturerIdentifier);
							}
						} catch (IOException e) {
		                    LOG_ERRROR("set_PlatformInformation", e.getMessage());
						}
					}
					rdns = x500Name.getRDNs(TrustiPhiStyle.platformModel);
					if(rdns != null && rdns.length > 0 && rdns[0].getFirst() != null)
					{
						platformCertificateData.setPlatformModel(rdns[0].getFirst().getValue().toString());
					}
					rdns = x500Name.getRDNs(TrustiPhiStyle.platformVersion);
					if(rdns != null && rdns.length > 0 && rdns[0].getFirst() != null)
					{
						platformCertificateData.setPlatformVersion(rdns[0].getFirst().getValue().toString());
					}
					rdns = x500Name.getRDNs(TrustiPhiStyle.platformSerial);
					if(rdns != null && rdns.length > 0 && rdns[0].getFirst() != null)
					{
						platformCertificateData.setPlatformSerial(rdns[0].getFirst().getValue().toString());
					}
				}
			}
		}
	}
	
	
	/***
	 * Set the JAXB fields of found in the CRLDistPoint object
	 * 
	 * If the CRLDistPoint is null don't change the input PlatformCertificateData.
	 * 
	 * @param[out] platformCertificateData
	 */
	private void set_CRLDistPointFields(PlatformCertificateData platformCertificateData)
	{
	    if(this.cRLDistPoint == null)
        {
            return;
        }
        
        List<XmlCRLDistributionPoints> jaxbCRLDistributionPoints = new ArrayList<XmlCRLDistributionPoints>();
        DistributionPoint[] pointInfoArray = this.cRLDistPoint.getDistributionPoints();        

        if(pointInfoArray != null)
        {
            for(DistributionPoint pointInfo: pointInfoArray)
            {
                XmlCRLDistributionPoints xmlCRLDistributionPoints = new XmlCRLDistributionPoints();
                
                if (pointInfo.getDistributionPoint() != null)
                {
                    DistributionPointName distributionPoint = pointInfo.getDistributionPoint();
                    XmlDistributionPointName xmlDistributionPointName = new XmlDistributionPointName();
                    List<XmlGeneralName> xmlGeneralName_array = null;
                    GeneralName[] generalNames = ((GeneralNames) distributionPoint.getName()).getNames();
                    
                    // choice: either fullName or nameRelativeToCRLIssuer
                    if (distributionPoint.getType() == 0)
                    {
                        // fullName
                        xmlGeneralName_array = xmlDistributionPointName.getFullname();
                    }
                    else
                    {
                        // nameRelativeToCRLIssuer
                        xmlGeneralName_array = xmlDistributionPointName.getNameRelativeToCRLIssuer();
                    }
                    for (GeneralName generalName : generalNames)
                    {
                        XmlGeneralName xmlGeneralName = new XmlGeneralName();
                        
                        xmlGeneralName.setName(generalName.getName().toString());
                        
                        xmlGeneralName.setTag(XmlGeneralNameTag.fromValue(ParsingUtils.getGeneralNameTagStringValue(
                                generalName.getTagNo())));
                        xmlGeneralName_array.add(xmlGeneralName);
                    }
                    xmlCRLDistributionPoints.setDistributionPoint(xmlDistributionPointName);
                }                

                if (pointInfo.getReasons() != null)
                {
                    byte[] reasonBytes = pointInfo.getReasons().getBytes();
                    
                    // convert bytes to string of 1s and 0s
                    int size = reasonBytes.length * Byte.SIZE;
                    StringBuilder sb = new StringBuilder(size);
                    
                    for( int i = 0; i < size; i++ )
                    {
                        sb.append((reasonBytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
                    }
                    xmlCRLDistributionPoints.setReasons(sb.toString());    
                }
                
                if (pointInfo.getCRLIssuer() != null && pointInfo.getCRLIssuer().getNames() != null)
                {
                    GeneralName cRLIssuer = pointInfo.getCRLIssuer().getNames()[0];
                    XmlGeneralName cRLIssuerInfo = new XmlGeneralName();
                    
                    cRLIssuerInfo.setTag(XmlGeneralNameTag.fromValue(ParsingUtils.getGeneralNameTagStringValue(
                            cRLIssuer.getTagNo())));
                    
                    cRLIssuerInfo.setName(cRLIssuer.getName().toString());
                    
                    xmlCRLDistributionPoints.setCRLIssuer(cRLIssuerInfo);
                }
                
                jaxbCRLDistributionPoints.add(xmlCRLDistributionPoints);
            }
        }
        
        platformCertificateData.getCRLDistributionPoints().addAll(jaxbCRLDistributionPoints);
	}
	
	public void setHolder(AttributeCertificateHolder attributeCertificateHolder)
	{
		attr_cert_holder = attributeCertificateHolder;
	}
	
	private void updateAsNeeded() throws IOException, OperatorCreationException
	{
		if(dirtyBit) {
			if(privateKey != null)
			{
				updatePlatformCertificateHolder(privateKey);
			}
			else {
				throw new IOException("Failed to update PlatformCertificateHolder (for output or verification) after modifications; PrivateKey Not Set!");
			}
		}
	}
	
	private void LOG_ERRROR(String methodName, String errString)
	{
		System.out.println("[PlatformCertificateHolder." + methodName + "] ERROR: " + errString);
	}

	// complete certificate, set on load and output on write 
	private	X509AttributeCertificateHolder attributeCertHolder=null;
	
	// component parts for individual data set and get functions
	private	AttributeCertificateIssuer issuer=null;
	private	AttributeCertificateHolder attr_cert_holder=null;
	private	BigInteger                 platform_cert_serial_num = null;
	private	Date                       notBefore=null;
	private	Date                       notAfter=null;
	private	TcgPlatformSpecification   tcgPlatformSpecification=null;
	private TcgCredentialSpecification tcgCredentialSpecification=null;
	private	TbbSecurityAssertions      tbbSecurityAssertions = null;
	private	CertificatePolicies        certificate_policies=null;
	private	AuthorityKeyIdentifier     authorityKeyIdentifier=null;
	private	AuthorityInformationAccess authorityInformationAccess=null;
	private	GeneralNames               subjectAltName=null;
	private CRLDistPoint               cRLDistPoint=null;
	private URIReference               platformConfigUri=null;
	private PlatformConfiguration      platformConfiguration=null;
	private	String                     signatureAlgorithm=null;
	private	byte[]                     signatureValue=null;
	private	PrivateKey                 privateKey=null;
	private boolean                    extIsCrticalCertificatePolicies=false;
	private boolean                    extIsCrticalSubjectAltName=false;
	private boolean                    extIsCrticalAuthKeyID=false;
	private boolean                    extIsCrticalAuthInfoAccess=false;
	private boolean                    extIsCrticalCrlDist=false;
	private	boolean                    dirtyBit = false;
}
