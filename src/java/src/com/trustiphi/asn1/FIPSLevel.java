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

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 *    ASN1 structure.
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
 *      
 */
public class FIPSLevel extends Asn1Translator {
	private String  version=null;
	private Integer level=null;
	private Boolean plus=null;
	
	public static final String Version_140_1 = "140-1";
	public static final String Version_140_2 = "140-2";
	
	/**
	 * Create an empty FIPSLevel
	 */
	public FIPSLevel() {
	}
	
	/**
	 * Create a FIPSLevel initialized with the input values
	 */
	public FIPSLevel(String version, Integer level, Boolean plus) {
		this.version = version;
		this.level = level;
		this.plus = plus;
	}

	/**
	 * Create a FIPSLevel from an ASN1Sequence.
	 * The ASN1Sequence should be formatted correctly and contain the correct information.
	 * If it is missing information it is not assigned.  If an unexpected format is encountered
	 * an IOException is thrown.
	 * 
	 * The expected format is:
	 * 
	 * 	ASN1Sequence
	 * 		Version       DERIA5String/DERUTF8String
	 * 		securityLevel ASN1Enumerated
	 * 		plus          ASN1Boolean
	 * 
	 * @param fipsLevelEncodable
	 * @throws IOException if unexpected ASN1 formatting is encountered
	 */
	public FIPSLevel(ASN1Encodable fipsLevelEncodable) 
		throws IOException
	{
		if(fipsLevelEncodable instanceof ASN1Sequence)
		{
			ASN1Encodable[] fipsLevelArray = ((ASN1Sequence) fipsLevelEncodable).toArray();
			if(fipsLevelArray.length > 0)
			{
				if(fipsLevelArray[0] instanceof DERIA5String)
				{
					this.version = ((DERIA5String)fipsLevelArray[0]).toString();
				}
				else if(fipsLevelArray[0] instanceof DERUTF8String)
				{
					this.version = ((DERUTF8String)fipsLevelArray[0]).toString();
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing FIPSLevel.version. Expected ASN1 String type; Found " 
									+ fipsLevelArray[0].getClass().toString());
				}
			}
			if(fipsLevelArray.length > 1)
			{
				if(fipsLevelArray[1] instanceof ASN1Enumerated)
				{
					this.level = new Integer(((ASN1Enumerated)fipsLevelArray[1]).getValue().intValue());
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing FIPSLevel.level. Expected ASN1Enumerated type; Found " 
									+ fipsLevelArray[1].getClass().toString());
				}
			}
			if(fipsLevelArray.length > 2)
			{
				if(fipsLevelArray[2] instanceof ASN1Boolean)
				{
					this.plus = new Boolean(((ASN1Boolean)fipsLevelArray[2]).isTrue());
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing FIPSLevel.plus. Expected ASN1Boolean type; Found " 
									+ fipsLevelArray[2].getClass().toString());
				}
			}
		}
		else {
			// unexpected type
			throw new IOException(
					"Unexpected ASN1 formatting while parsing FIPSLevel. Expected ASN1Sequence type; Found " 
							+ fipsLevelEncodable.getClass().toString());
		}
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		int numFields;
		if(plus == null)
		{
			numFields = 2;
		}
		else {
			numFields = 3;
		}
		
		ASN1Encodable[] outputArray = new ASN1Encodable[numFields];
		if(version != null)
		{
			outputArray[0] = new DERIA5String(version);
		} else {
			outputArray[0] = null;
		}
		if(level != null)
		{
			outputArray[1] = new ASN1Enumerated(level);
		} else {
			outputArray[1] = null;
		}
		if(plus != null)
		{
			outputArray[2] = ASN1Boolean.getInstance(plus.booleanValue());
		}
		
		return new DERSequence(outputArray);
	}
	
	/**
	 * @return the version
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * @param version the version to set
	 */
	public void setVersion(String version) {
		this.version = version;
	}

	/**
	 * @return the level
	 */
	public Integer getLevel() {
		return level;
	}

	/**
	 * @param level the level to set
	 */
	public void setLevel(Integer level) {
		this.level = level;
	}

	/**
	 * @return the plus
	 */
	public Boolean getPlus() {
		return plus;
	}

	/**
	 * @param plus the plus to set
	 */
	public void setPlus(Boolean plus) {
		this.plus = plus;
	}
}
