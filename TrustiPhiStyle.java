package com.trustiphi.tpm2verification;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class TrustiPhiStyle extends BCStyle {

	/**
	 * SubjectAlternativeName
	 */
	public static final ASN1ObjectIdentifier SubjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17");

	/**
	 * CertificatePolicies
	 */
	public static final ASN1ObjectIdentifier CertificatePolicies = new ASN1ObjectIdentifier("2.5.29.32");

	/**
	 * authorityKeyIdentifier
	 */
	public static final ASN1ObjectIdentifier AuthorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35");

	/**
	 * tcg-at-platformManufacturer
	 */
	public static final ASN1ObjectIdentifier platformManufacturer = new ASN1ObjectIdentifier("2.23.133.2.4");

	/**
	 * tcg-at-platformManufacturerStr
	 */
	public static final ASN1ObjectIdentifier platformManufacturerStr = new ASN1ObjectIdentifier("2.23.133.5.1.1");

	/**
	 * tcg-at-platformManufacturerId
	 */
	public static final ASN1ObjectIdentifier platformManufacturerId = new ASN1ObjectIdentifier("2.23.133.5.1.2");

	/**
	 * tcg-at-platformConfigUri
	 */
	public static final ASN1ObjectIdentifier platformConfigUri = new ASN1ObjectIdentifier("2.23.133.5.1.3");

	/**
	 * tcg-at-platformModel
	 */
//	public static final ASN1ObjectIdentifier platformModel = new ASN1ObjectIdentifier("2.23.133.2.5"); OLD VALUE
	public static final ASN1ObjectIdentifier platformModel = new ASN1ObjectIdentifier("2.23.133.5.1.4");

	/**
	 * tcg-at-platformVersion
	 */
//	public static final ASN1ObjectIdentifier platformVersion = new ASN1ObjectIdentifier("2.23.133.2.6"); OLD VALUE
	public static final ASN1ObjectIdentifier platformVersion = new ASN1ObjectIdentifier("2.23.133.5.1.5");

	/**
	 * tcg-at-tcgPlatformSpecification
	 */
	public static final ASN1ObjectIdentifier tcgPlatformSpecification = new ASN1ObjectIdentifier("2.23.133.2.17");

	/**
	 * tcg-at-tbbSecurityAssertions
	 */
	public static final ASN1ObjectIdentifier tbbSecurityAssertions = new ASN1ObjectIdentifier("2.23.133.2.19");

	/**
	 * platformSerial
	 */
//	public static final ASN1ObjectIdentifier platformSerial = new ASN1ObjectIdentifier("2.23.133.2.23");
	public static final ASN1ObjectIdentifier platformSerial = new ASN1ObjectIdentifier("2.23.133.5.1.6");

	/**
	 * unotice
	 */
	public static final ASN1ObjectIdentifier unotice = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2");

	/*
	 * Singleton instance
	 */
	public static final X500NameStyle INSTANCE = new TrustiPhiStyle();
	
	protected TrustiPhiStyle () 
	
	{
		super();
		
		defaultSymbols.put(SubjectAlternativeName, "subjectAlternativeName");
		defaultSymbols.put(CertificatePolicies, "certificatePolicies");
		defaultSymbols.put(platformManufacturer, "platformManufacturer");
		defaultSymbols.put(platformManufacturerStr, "platformManufacturerStr");
		defaultSymbols.put(platformManufacturerId, "platformManufacturerId");
		defaultSymbols.put(platformConfigUri, "platformConfigUri");
		defaultSymbols.put(platformModel, "platformModel");
		defaultSymbols.put(platformVersion, "platformVersion");
		defaultSymbols.put(tbbSecurityAssertions, "tbbSecurityAssertions");
		defaultSymbols.put(platformSerial, "platformSerial");
		defaultSymbols.put(unotice, "unotice");

		defaultLookUp.put("subjectalternativename", SubjectAlternativeName);
		defaultLookUp.put("certificatepolicies", CertificatePolicies);
		defaultLookUp.put("platformmanufacturer", platformManufacturer);
		defaultLookUp.put("platformmanufacturerStr", platformManufacturerStr);
		defaultLookUp.put("platformmanufacturerId", platformManufacturerId);
		defaultLookUp.put("platformconfiguri", platformConfigUri);
		defaultLookUp.put("platformmodel", platformModel);
		defaultLookUp.put("platformversion", platformVersion);
		defaultLookUp.put("tbbSecurityassertions", tbbSecurityAssertions);
		defaultLookUp.put("platformserial", platformSerial);
		defaultLookUp.put("unotice", unotice);
	}
}
