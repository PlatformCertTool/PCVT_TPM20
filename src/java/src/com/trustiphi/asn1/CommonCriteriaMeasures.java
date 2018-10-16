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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

/**
 *	ASN1 Structure
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
 */
public class CommonCriteriaMeasures extends Asn1Translator {
	private DERIA5String         version=null;
	private Integer              assuranceLevel=null;
	private Integer              evaluationStatus=null;
	private Boolean              plus=null;
	private Integer              strengthOfFunction=null;
	private ASN1ObjectIdentifier profileOid=null;
	private URIReference         profileUri=null;
	private ASN1ObjectIdentifier targetOid=null;
	private URIReference         targetUri=null;

	/**
	 * Create an empty CommonCriteriaMeasures
	 */
	public CommonCriteriaMeasures() {
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * Create a CommonCriteriaMeasures object with the input values for the required elements
	 */
	public CommonCriteriaMeasures(DERIA5String version, Integer assuranceLevel, Integer evaluationStatus) {
		this.version = version;
		this.assuranceLevel = assuranceLevel;
		this.evaluationStatus = evaluationStatus;
	}
	

	/**
	 * Create a CommonCriteriaMeasures from an ASN1Sequence.
	 * The ASN1Sequence should be formatted correctly and contain the correct information.
	 * If it is missing information it is not assigned.  If an unexpected format is encountered
	 * an IOException is thrown.
	 * 
	 * The expected format is:
	 * 
	 *    ASN1Sequence
	 *      version            DERIA5STRING
	 *      assurancelevel     ASN1Enumerated
	 *      evaluationStatus   ASN1Enumerated
	 *      plus               ASN1Boolean (DEFAULT FALSE)
	 *      strengthOfFunction ASN1TaggedObject[0] or ASN1Enumerated OPTIONAL,
	 *      profileOid         ASN1TaggedObject[1] or ASN1ObjectIdentifier OPTIONAL,
	 *      profileUri         ASN1TaggedObject[2] or URIReference OPTIONAL,
	 *      targetOid          ASN1TaggedObject[3] or ASN1ObjectIdentifier OPTIONAL,
	 *      targetUri          ASN1TaggedObject[4] or URIReference OPTIONAL }
	 * 
	 * @param ccMeasuresEncodable
	 * @throws IOException
	 */
	public CommonCriteriaMeasures(ASN1Encodable ccMeasuresEncodable) 
		throws IOException
	{
		if(ccMeasuresEncodable instanceof ASN1Sequence)
		{
			ASN1Encodable[] ccMeasures = ((ASN1Sequence) ccMeasuresEncodable).toArray();
			if(ccMeasures.length > 0)
			{
				if(ccMeasures[0] instanceof DERIA5String)
				{
					this.version = (DERIA5String) ccMeasures[0];
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.version. Expected DERIA5String type; Found " 
									+ ccMeasures[0].getClass().toString());
				}
				
			}
			if(ccMeasures.length > 1)
			{
				if(ccMeasures[1] instanceof ASN1Enumerated)
				{
					this.assuranceLevel = new Integer(((ASN1Enumerated) ccMeasures[1]).getValue().intValue());
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.assuranceLevel. Expected ASN1Enumerated type; Found " 
									+ ccMeasures[1].getClass().toString());
				}
			}
			if(ccMeasures.length > 2)
			{
				if(ccMeasures[2] instanceof ASN1Enumerated)
				{
					this.evaluationStatus = new Integer(((ASN1Enumerated) ccMeasures[2]).getValue().intValue());
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.evaluationStatus. Expected ASN1Enumerated type; Found " 
									+ ccMeasures[2].getClass().toString());
				}
			}
			int ccmIdx=3; // plus is optional, so keep track of the index of the next field to read
			if(ccMeasures.length > ccmIdx)
			{
				// this is an optional field, so if the 4th field is not
				// a Boolean assume there is no plus field
				if(ccMeasures[3] instanceof ASN1Boolean)
				{
					this.plus = new Boolean(((ASN1Boolean) ccMeasures[3]).isTrue());
					ccmIdx = 4; // the field at index 3 was plus so next field to parse is at index 4
				}
			}
			
			for(; ccmIdx < ccMeasures.length; ccmIdx++)
			{
				if(ccMeasures[ccmIdx] instanceof ASN1TaggedObject)
				{
					ASN1TaggedObject ccmTaggedObj = (ASN1TaggedObject) ccMeasures[ccmIdx];
					int ccmElemTag = ccmTaggedObj.getTagNo();
					if(ccmElemTag == 0)
					{
						if(ccmTaggedObj.getObject() instanceof ASN1Enumerated)
						{
							this.strengthOfFunction = new Integer(((ASN1Enumerated) ccmTaggedObj.getObject()).getValue().intValue());
						}
						else if (ccmTaggedObj.getObject() instanceof DEROctetString)
						{
						    this.strengthOfFunction = new Integer(ASN1Enumerated.getInstance(ccmTaggedObj, false).getValue().intValue());
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.strengthOfFunction."
									+ " Expected ASN1Enumerated or DEROctetString type; Found " 
											+ ccmTaggedObj.getObject().getClass().toString());
						}
					}
					else if(ccmElemTag == 1)
					{
						if(ccmTaggedObj.getObject() instanceof ASN1ObjectIdentifier)
						{
							this.profileOid = (ASN1ObjectIdentifier) ccmTaggedObj.getObject();
						}
						else if (ccmTaggedObj.getObject() instanceof DEROctetString) 
						{
						    this.profileOid = ASN1ObjectIdentifier.getInstance(ccmTaggedObj, false);
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.profileOid. "
									+ "Expected ASN1ObjectIdentifier or DEROctetString type; Found " 
											+ ccmTaggedObj.getObject().getClass().toString());
						}
					}
					else if(ccmElemTag == 2)
					{
						if(ccmTaggedObj.getObject() instanceof ASN1Sequence) // URIReference should be ASN1Sequence as outmost object
						{
							this.profileUri = new URIReference(ccmTaggedObj.getObject());
						}
						else if(ccmTaggedObj.getObject() instanceof DERIA5String) // URIReference should be ASN1Sequence as outmost object
						{
							this.profileUri = new URIReference((DERIA5String) ccmTaggedObj.getObject(), null, null);
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.profileUri. Expected ASN1Sequence type; Found " 
											+ ccmTaggedObj.getObject().getClass().toString());
						}
					}
					else if(ccmElemTag == 3)
					{
						if(ccmTaggedObj.getObject() instanceof ASN1ObjectIdentifier)
						{
							this.targetOid = (ASN1ObjectIdentifier) ccmTaggedObj.getObject();
						}
						else if (ccmTaggedObj.getObject() instanceof DEROctetString)
						{
						    this.targetOid = ASN1ObjectIdentifier.getInstance(ccmTaggedObj, false);
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.targetOid. "
									+ "Expected ASN1ObjectIdentifier or DEROctetString type; Found " 
											+ ccmTaggedObj.getObject().getClass().toString());
						}
					}
					else if(ccmElemTag == 4)
					{
						if(ccmTaggedObj.getObject() instanceof ASN1Sequence) // URIReference should be ASN1Sequence as outmost object
						{
							this.targetUri = new URIReference(ccmTaggedObj.getObject());
						}
						else if(ccmTaggedObj.getObject() instanceof DERIA5String) // URIReference should be ASN1Sequence as outmost object
						{
							this.targetUri = new URIReference((DERIA5String) ccmTaggedObj.getObject(), null, null);
						}
						else {
							// unexpected type
							throw new IOException(
									"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.targetUri. Expected ASN1Sequence type; Found " 
											+ ccmTaggedObj.getObject().getClass().toString());
						}
					}
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing CommonCriteriaMeasures.plus. Expected ASN1Boolean type; Found " 
									+ ccMeasures[3].getClass().toString());
				}
			}
		}
		else {
			// unexpected type
			throw new IOException(
					"Unexpected ASN1 formatting while parsing URIReference. Expected ASN1Sequence type; Found " 
							+ ccMeasuresEncodable.getClass().toString());
		}
	}
	
	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		// create space for in the output array for the non-optional and non-default
		//  value fields as well as any additional fields that are set
		int numElems=3;
		if(this.plus != null) {
			numElems++;
		}
		if(this.strengthOfFunction != null) {
			numElems++;
		}
		if(this.profileOid != null) {
			numElems++;
		}
		if(this.profileUri != null) {
			numElems++;
		}
		if(this.targetOid != null) {
			numElems++;
		}
		if(this.targetUri != null) {
			numElems++;
		}
		
		ASN1Encodable[] outputArray = new ASN1Encodable[numElems];
		
		outputArray[0] = version;
		outputArray[1] = new ASN1Enumerated(assuranceLevel);
		outputArray[2] = new ASN1Enumerated(evaluationStatus);
		int idx = 3;
		if(this.plus != null) {
			outputArray[idx++] = ASN1Boolean.getInstance(plus.booleanValue());
		}
		if(this.strengthOfFunction != null) {
			outputArray[idx++] = new DERTaggedObject(false, 0, new ASN1Enumerated(strengthOfFunction));
		}
		if(this.profileOid != null) {
			outputArray[idx++] = new DERTaggedObject(false, 1, profileOid);
		}
		if(this.profileUri != null) {
			outputArray[idx++] = new DERTaggedObject(false, 2, profileUri);
		}
		if(this.targetOid != null) {
			outputArray[idx++] = new DERTaggedObject(false, 3, targetOid);
		}
		if(this.targetUri != null) {
			outputArray[idx++] = new DERTaggedObject(false, 4, targetUri);
		}
		
		return new DLSequence(outputArray);
	}

	/**
	 * @return the version
	 */
	public DERIA5String getVersion() {
		return version;
	}

	/**
	 * @param version the version to set
	 */
	public void setVersion(DERIA5String version) {
		this.version = version;
	}

	/**
	 * @return the assuranceLevel
	 */
	public Integer getAssurancelevel() {
		return assuranceLevel;
	}

	/**
	 * @param assurancelevel the assuranceLevel to set
	 */
	public void setAssurancelevel(Integer assurancelevel) {
		this.assuranceLevel = assurancelevel;
	}

	/**
	 * @return the evaluationStatus
	 */
	public Integer getEvaluationStatus() {
		return evaluationStatus;
	}

	/**
	 * @param evaluationStatus the evaluationStatus to set
	 */
	public void setEvaluationStatus(Integer evaluationStatus) {
		this.evaluationStatus = evaluationStatus;
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

	/**
	 * @return the strengthOfFunction
	 */
	public Integer getStrengthOfFunction() {
		return strengthOfFunction;
	}

	/**
	 * @param strengthOfFunction the strengthOfFunction to set
	 */
	public void setStrengthOfFunction(Integer strengthOfFunction) {
		this.strengthOfFunction = strengthOfFunction;
	}

	/**
	 * @return the profileOid
	 */
	public ASN1ObjectIdentifier getProfileOid() {
		return profileOid;
	}

	/**
	 * @param profileOid the profileOid to set
	 */
	public void setProfileOid(ASN1ObjectIdentifier profileOid) {
		this.profileOid = profileOid;
	}

	/**
	 * @return the profileUri
	 */
	public URIReference getProfileUri() {
		return profileUri;
	}

	/**
	 * @param profileUri the profileUri to set
	 */
	public void setProfileUri(URIReference profileUri) {
		this.profileUri = profileUri;
	}

	/**
	 * @return the targetOid
	 */
	public ASN1ObjectIdentifier getTargetOid() {
		return targetOid;
	}

	/**
	 * @param targetOid the targetOid to set
	 */
	public void setTargetOid(ASN1ObjectIdentifier targetOid) {
		this.targetOid = targetOid;
	}

	/**
	 * @return the targetUri
	 */
	public URIReference getTargetUri() {
		return targetUri;
	}

	/**
	 * @param targetUri the targetUri to set
	 */
	public void setTargetUri(URIReference targetUri) {
		this.targetUri = targetUri;
	}
}
