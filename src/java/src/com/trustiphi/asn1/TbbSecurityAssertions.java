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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

/**
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
 *      
 *    Version ::= INTEGER { v1(0) }
 *     
 *    FIPSLevel ::= SEQUENCE {
 *      version IA5STRING, -- "140-1" or "140-2"
 *      level SecurityLevel,
 *      plus BOOLEAN DEFAULT FALSE }
 *      
 *    MeasurementRootType ::= ENUMERATED {
 *      static  (0),
 *      dynamic (1),
 *      nonHost (2) }
 *   
 *
 *
 */
public class TbbSecurityAssertions extends Asn1Translator {
	private Integer                version=null;
	private CommonCriteriaMeasures ccInfo=null;
	private FIPSLevel              fipsLevel=null;
	private Integer                rtmType=null;
	private Boolean                iso9000Certified=null;
	private String                 iso9000Uri=null;

	public static final Integer Version_V1 = new Integer(0);
	
	/**
	 * Create an empty TbbSecurityAssertions
	 */
	public TbbSecurityAssertions() {
	}
	
	/**
	 * Create an empty TbbSecurityAssertions
	 */
	public TbbSecurityAssertions(Integer version, 
			                     CommonCriteriaMeasures ccInfo, 
			                     FIPSLevel fipsLevel, 
			                     Integer rtmType, 
			                     Boolean iso9000Certified, 
			                     String iso9000Uri) 
	{
		this.version = version;
		this.ccInfo = ccInfo;
		this.fipsLevel = fipsLevel;
		this.rtmType = rtmType;
		this.iso9000Certified = iso9000Certified;
		this.iso9000Uri = iso9000Uri;
	}

	/**
	 * Create a TbbSecurityAssertions from an ASN1Sequence.
	 * The ASN1Sequence should be formatted correctly and contain the correct information.
	 * If it is missing information it is not assigned.  If an unexpected format is encountered
	 * an IOException is thrown.
	 * 
	 * The expected format is:
	 * 
	 * 	ASN1Sequence
	 * 		Version          ASN1Integer DEFAULT 0 (v1)
	 * 		ccInfo           TAGGED 0 CommonCrireriaMeasures OPTIONAL
	 * 		fipsLevel        TAGGED 1 FIPSLevel OPTIONAL
	 * 		rtmType          TAGGED 2 ASN1Enumerated OPTIONAL
	 * 		iso9000Certified ASN1Boolean DEFAULT FALSE
	 * 		iso9000Uri       DERIA5STRING
	 * 
	 * @param tbbSecurityAssertionsEncodable
	 * @throws IOException if unexpected ASN1 formatting is encountered
	 */
	public TbbSecurityAssertions(ASN1Encodable tbbSecurityAssertionsEncodable) 
		throws IOException
	{
		if(tbbSecurityAssertionsEncodable instanceof ASN1Sequence)
		{
			ASN1Encodable[] securityAssertions = ((ASN1Sequence) tbbSecurityAssertionsEncodable).toArray();
			
			// the first field is version (INTEGER), which is optional
			int secAssertionsIdx = 0;
			if(securityAssertions.length > 0)
			{
				if(securityAssertions[0] instanceof ASN1Integer)
				{
					this.version = new Integer(((ASN1Integer)securityAssertions[0]).getValue().intValue());
					secAssertionsIdx++;
				}
			}

			// Next 3 fields are optional ASN1 Tagged fields - loop through them (3 times)
			// If a Boolean or IA5STRING is encountered then the ASN1Tagged elements and are we likely passed and the
			// element is the (optional) iso9000Certified field or the iso9000Uri field.

			int maxTaggedObjectIndex = secAssertionsIdx + 3; // 3 if there is was no version field, 4 if there was
			for(; secAssertionsIdx < maxTaggedObjectIndex && secAssertionsIdx < securityAssertions.length; secAssertionsIdx++)
			{
				if(securityAssertions[secAssertionsIdx] instanceof ASN1TaggedObject)
				{
					ASN1TaggedObject saTaggedObj = (ASN1TaggedObject) securityAssertions[secAssertionsIdx];
					int saElemTag = saTaggedObj.getTagNo();
					if(saElemTag == 0) // ccInfo
					{
						this.ccInfo = new CommonCriteriaMeasures(saTaggedObj.getObject());
					}
					if(saElemTag == 1) // fipsLevel
					{
						this.fipsLevel = new FIPSLevel(saTaggedObj.getObject());
					}
					if(saElemTag == 2) // rtmType
					{
						if(saTaggedObj.getObject() instanceof ASN1Enumerated)
						{
							this.rtmType = new Integer(((ASN1Enumerated)saTaggedObj.getObject()).getValue().intValue());
						}
						else if(saTaggedObj.getObject() instanceof ASN1OctetString)
						{
							ASN1OctetString rtmTypeOctetString = (ASN1OctetString) saTaggedObj.getObject();
							byte[] rtmTypeBytes = rtmTypeOctetString.getOctets();
							int rtmType_int = -1;
							if(rtmTypeBytes.length == 1)
							{
								// treat as an integer value
								rtmType_int = rtmTypeBytes[0];
							}
							else {
								try {
									String s = new String(rtmTypeBytes, "UTF-8");
									rtmType_int = Integer.parseInt(s);
								} 
								catch (Exception e) {
									String s = String.valueOf(ByteUtils.toCharArray(rtmTypeBytes));
									rtmType_int = Integer.parseInt(s);
								}
							}
							this.rtmType = new Integer(rtmType_int);
						}
						else if(saTaggedObj.getObject() instanceof ASN1Integer)
						{
							this.rtmType = new Integer(((ASN1Integer)saTaggedObj.getObject()).getValue().intValue());
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing TbbSecurityAssertions.rtmType. Expected ASN1Enumerated type; Found " 
											+ saTaggedObj.getObject().getClass().toString());
						}
					}
				}
				else
				{
					// no more optional tagged objects
					break;
				}
			}
			
			if(secAssertionsIdx < securityAssertions.length && 
					securityAssertions[secAssertionsIdx] instanceof ASN1Boolean) // iso9000Certified 
			{
				this.iso9000Certified = new Boolean(((ASN1Boolean)securityAssertions[secAssertionsIdx]).isTrue());
				secAssertionsIdx++;
			}

			if(secAssertionsIdx < securityAssertions.length)// iso9000Uri
			{
				if(securityAssertions[secAssertionsIdx] instanceof DERIA5String)  
				{
					this.iso9000Uri = ((DERIA5String)securityAssertions[secAssertionsIdx]).getString();
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing TbbSecurityAssertions.iso9000Uri. Expected DERIA5String type; Found " 
									+ securityAssertions[secAssertionsIdx].getClass().toString());
				}
			}
			else {
				// iso900Uri is a required field
				// not currently enforcing that required fields are there
				//throw new IOException(
				//		"Unexpected ASN1 formatting while parsing TbbSecurityAssertions.iso9000Uri. Missing required field!");
			}
		}
		else {
			// unexpected type
			throw new IOException(
					"Unexpected ASN1 formatting while parsing TbbSecurityAssertions. Expected ASN1Sequence type; Found " 
							+ tbbSecurityAssertionsEncodable.getClass().toString());
		}
	}
	
	/**
	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector secAssertionsArray = new ASN1EncodableVector();
		
		if(version != null)
		{
			secAssertionsArray.add(new ASN1Integer(version.longValue()));
		}

		if(ccInfo != null)
		{
			secAssertionsArray.add(new DERTaggedObject(false, 0, ccInfo));
		}
		
		if(fipsLevel != null)
		{
			secAssertionsArray.add(new DERTaggedObject(false, 1, fipsLevel));
		}
		
		if(rtmType != null)
		{
			secAssertionsArray.add(new DERTaggedObject(false, 2, new ASN1Enumerated(rtmType)));
		}
		
		if(iso9000Certified != null)
		{
			secAssertionsArray.add(ASN1Boolean.getInstance(iso9000Certified.booleanValue()));
		}
		
		if(iso9000Uri != null)
		{
			secAssertionsArray.add(new DERIA5String(iso9000Uri));
		}
		
		return new DERSequence(secAssertionsArray);
	}

	/**
	 * @return the version
	 */
	public Integer getVersion() {
		return version;
	}

	/**
	 * @param version the version to set
	 */
	public void setVersion(Integer version) {
		this.version = version;
	}

	/**
	 * @return the ccInfo
	 */
	public CommonCriteriaMeasures getCcInfo() {
		return ccInfo;
	}

	/**
	 * @param ccInfo the ccInfo to set
	 */
	public void setCcInfo(CommonCriteriaMeasures ccInfo) {
		this.ccInfo = ccInfo;
	}

	/**
	 * @return the fipsLevel
	 */
	public FIPSLevel getFipsLevel() {
		return fipsLevel;
	}

	/**
	 * @param fipsLevel the fipsLevel to set
	 */
	public void setFipsLevel(FIPSLevel fipsLevel) {
		this.fipsLevel = fipsLevel;
	}

	/**
	 * @return the rtmType
	 */
	public Integer getRtmType() {
		return rtmType;
	}

	/**
	 * @param rtmType the rtmType to set
	 */
	public void setRtmType(Integer rtmType) {
		this.rtmType = rtmType;
	}

	/**
	 * @return the iso9000Certified
	 */
	public Boolean getIso9000Certified() {
		return iso9000Certified;
	}

	/**
	 * @param iso9000Certified the iso9000Certified to set
	 */
	public void setIso9000Certified(Boolean iso9000Certified) {
		this.iso9000Certified = iso9000Certified;
	}

	/**
	 * @return the iso9000Uri
	 */
	public String getIso9000Uri() {
		return iso9000Uri;
	}

	/**
	 * @param iso9000Uri the iso9000Uri to set
	 */
	public void setIso9000Uri(String iso9000Uri) {
		this.iso9000Uri = iso9000Uri;
	}
}
