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

package com.trustiphi.asn1;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;

/**
 *    ASN1 structure.
 * 
 * 
 * TCGPlatformSpecification ::= SEQUENCE {
 * 		Version TCGSpecificationVersion,
 * 		platformClass OCTET STRING SIZE(4) }
 *
 * TCGSpecificationVersion ::= SEQUENCE {
 * 		majorVersion INTEGER,
 * 		minorVersion INTEGER,
 * 		revision INTEGER }
 * 
 */
public class TcgPlatformSpecification extends Asn1Translator {
	private String  platformClass=null;
	private Integer majorVersion=null;
	private Integer minorVersion=null;
	private Integer revision=null;
	
	/**
	 * Create an empty TcgPlatformSpecification
	 */
	public TcgPlatformSpecification() {
	}
	
	/**
	 * Create an TcgPlatformSpecification with input values
	 */
	public TcgPlatformSpecification(String platformClass, Integer majorVersion, Integer minorVersion, Integer revision) {
		this.platformClass = platformClass;
		this.majorVersion = majorVersion;
		this.minorVersion = minorVersion;
		this.revision = revision;
	}
	
	/**
	 * Create a TcgPlatformSpecification from an ASN1Sequence.
	 * The ASN1Sequence should be formatted correctly and contain the correct information.
	 * If it is missing information it is not assigned.  If an unexpected format is encountered
	 * an IOException is thrown.
	 * 
	 * The expected format is:
	 * 
	 * 	ASN1Sequence
	 * 		Version (ASN1Sequence)
	 * 			majorVersion (ASN1Integer)
	 * 			minorVersion (ASN1Integer)
	 * 			revision (ASN1Interger)
	 * 		platformClass (ASN1 String type - OctetString/UTF8String/AI5String.)
	 * 
	 * @param tcgPlatformSpecSet
	 * @throws IOException if unexpected ASN1 formatting is encountered 
	 */
	public TcgPlatformSpecification(ASN1Encodable tcgPlatformSpecEncodable) 
			throws IOException 
	{
		if(tcgPlatformSpecEncodable instanceof ASN1Sequence)
		{
			ASN1Sequence tcgPlatformSpec = (ASN1Sequence) tcgPlatformSpecEncodable;
			if(tcgPlatformSpec.size() > 0)
			{
				if(tcgPlatformSpec.toArray()[0] instanceof ASN1Sequence)
				{
					ASN1Sequence version = (ASN1Sequence) tcgPlatformSpec.toArray()[0];
					ASN1Encodable[] version_array = version.toArray();
					if(version_array.length > 0)
					{
						if(version_array[0] instanceof ASN1Integer)
						{
							this.majorVersion = new Integer(((ASN1Integer)version_array[0]).getValue().intValue()); 
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing TcgPlatformSpecification.Version.majorVersion. Expected ASN1Integer; Found " 
											+ version_array[0].getClass().toString());
						}
					}
					if(version_array.length > 1)
					{
						if(version_array[1] instanceof ASN1Integer)
						{
							this.minorVersion = new Integer(((ASN1Integer)version_array[1]).getValue().intValue()); 
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing TcgPlatformSpecification.Version.minorVersion. Expected ASN1Integer; Found " 
											+ version_array[1].getClass().toString());
						}
					}
					if(version_array.length > 2)
					{
						if(version_array[2] instanceof ASN1Integer)
						{
							this.revision = new Integer(((ASN1Integer)version_array[2]).getValue().intValue()); 
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing TcgPlatformSpecification.Version.revision. Expected ASN1Integer; Found " 
											+ version_array[2].getClass().toString());
						}
					}
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing TcgPlatformSpecification.Version. Expected ASN1Seqeunce; Found " 
									+ tcgPlatformSpec.toArray()[0].getClass().toString());
				}
			}
			if(tcgPlatformSpec.size() > 1)
			{
				ASN1Encodable platformClassEnc = tcgPlatformSpec.toArray()[1];
				if(platformClassEnc instanceof DEROctetString)
				{
					// The is the correct type according to the spec.  It should be 4 bytes.
					// Output as hex string
//					this.platformClass = ((DEROctetString)platformClassEnc).toString();
					this.platformClass = javax.xml.bind.DatatypeConverter.printHexBinary(((DEROctetString)platformClassEnc).getOctets());
					if(!this.platformClass.isEmpty())
					{
						this.platformClass = "0x" + this.platformClass;
					}
				}
				else if(platformClassEnc instanceof DERUTF8String)
				{
					this.platformClass = ((DERUTF8String)platformClassEnc).toString();
				}
				else if(platformClassEnc instanceof DERIA5String)
				{
					this.platformClass = ((DERIA5String)platformClassEnc).toString();
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing TcgPlatformSpecification.platformClass. Expected ASN1 String type; Found " 
									+ platformClassEnc.getClass().toString());
				}
			}
		}
		else {
			// unexpected type
			throw new IOException(
					"Unexpected ASN1 formatting while parsing TcgPlatformSpecification. Expected ASN1Seqeunce; Found " 
							+ tcgPlatformSpecEncodable.getClass().toString());
		}
	}
	
	/* (non-Javadoc)
	 * 
	 * 	DLSequence
	 * 		Version (DLSequence)
	 * 			majorVersion (ASN1Integer)
	 * 			minorVersion (ASN1Integer)
	 * 			revision (ASN1Interger)
	 * 		platformClass (DEROctetString)
	 * 
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1Encodable[] asn1EncodableArr = new ASN1Encodable[3];
		asn1EncodableArr[0] = asn1EncodableArr[1] = asn1EncodableArr[2] = null;
		if(majorVersion != null) {
			asn1EncodableArr[0] = new ASN1Integer(majorVersion.longValue());
		}
		if(minorVersion != null) {
			asn1EncodableArr[1] = new ASN1Integer(minorVersion.longValue());
		}
		if(revision != null) {
			asn1EncodableArr[2] = new ASN1Integer(revision.longValue());
		}
		DLSequence dlSequence = new DLSequence(asn1EncodableArr);
		asn1EncodableArr = new ASN1Encodable[2];
		asn1EncodableArr[0] = dlSequence;
		if(platformClass != null) {
			// remove 0x from start of hex string of it is there
			String platClass = platformClass.replaceFirst("0[xX]", ""); 
			byte[] sigbytes = new BigInteger(platClass, 16).toByteArray();
			int numsigbytes = sigbytes.length;
			byte[] bytes;
			if(numsigbytes >= 4)
			{
				bytes = sigbytes;
			}
			else {
				bytes = new byte[4];
				int sigb_idx = numsigbytes-1;
				for(int i=3; i >=0; i--)
				{
					if(sigb_idx >= 0)
					{
						bytes[i] = sigbytes[sigb_idx--];
					}
					else {
						bytes[i] = 0;
					}
				}
			}
				
			asn1EncodableArr[1] = new DEROctetString(bytes);
		}
		else {
			asn1EncodableArr[1] = null;
		}
		DLSequence asn1_platformSpec = new DLSequence(asn1EncodableArr);

		return asn1_platformSpec;
	}

	/**
	 * @return the platformClass
	 */
	public String getPlatformClass() {
		return platformClass;
	}

	/**
	 * @param platformClass the platformClass to set
	 */
	public void setPlatformClass(String platformClass) {
		this.platformClass = platformClass;
	}

	/**
	 * @return the majorVersion
	 */
	public Integer getMajorVersion() {
		return majorVersion;
	}

	/**
	 * @param majorVersion the majorVersion to set
	 */
	public void setMajorVersion(Integer majorVersion) {
		this.majorVersion = majorVersion;
	}

	/**
	 * @return the minorVersion
	 */
	public Integer getMinorVersion() {
		return minorVersion;
	}

	/**
	 * @param minorVersion the minorVersion to set
	 */
	public void setMinorVersion(Integer minorVersion) {
		this.minorVersion = minorVersion;
	}

	/**
	 * @return the revision
	 */
	public Integer getRevision() {
		return revision;
	}

	/**
	 * @param revision the revision to set
	 */
	public void setRevision(Integer revision) {
		this.revision = revision;
	}

}
