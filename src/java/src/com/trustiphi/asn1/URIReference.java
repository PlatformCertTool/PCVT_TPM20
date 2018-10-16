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

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 *	ASN1 Structure
 *
 *    -- Reference to external document containing information relevant to this subject. 
 *    -- The hashAlgorithm and hashValue MUST both exist in each reference if either 
 *    -- appear at all.
 *    URIReference ::= SEQUENCE {
 *      uniformResourceIdentifier IA5String,
 *      hashAlgorithm             AlgorithmIdentifier OPTIONAL,
 *      hashValue                 BIT STRING OPTIONAL }
 */
public class URIReference extends Asn1Translator {
	private DERIA5String        _uriRefId=null;
	private AlgorithmIdentifier _hashAlgorithm=null;
	private DERBitString        _hashValue=null;
	
	/**
	 * Create an empty URIReference
	 */
	public URIReference() {
	}

	
	
	/**
	 * Create a URIReference initialized with the input values
	 */
	public URIReference(DERIA5String uniformResourceIdentifier, AlgorithmIdentifier hashAlgorithm, DERBitString hashValue) {
		// A URIReference must have both hashAlgorithmID and hashValue or neither
		if((hashAlgorithm != null && hashValue == null) || (hashAlgorithm == null && hashValue != null))
		{
			throw new IllegalArgumentException("URIReference must contain both a hashAlgorithm identifier and a hashValue or neither");
		}
		
		_uriRefId = uniformResourceIdentifier;
		_hashAlgorithm = hashAlgorithm;
		_hashValue = hashValue;
	}

	
	

	/**
	 * Create a URIReference from an ASN1Sequence.
	 * The ASN1Sequence should be formatted correctly and contain the correct information.
	 * If it is missing information it is not assigned.  If an unexpected format is encountered
	 * an IOException is thrown.
	 * 
	 * The expected format is:
	 * 
	 * 	ASN1Sequence
	 * 		uniformResourceIdentifier DERIA5String
	 *      hashAlgorithm             AlgorithmIdentifier OPTIONAL (ASN1ObjectIdentifier will pass)
	 *      hashValue                 DERBitString OPTIONAL (ASN1BitString will pass)
	 * 
	 * 
	 * @param uriRefEncodable
	 * @throws IOException if unexpected ASN1 formatting is encountered
	 */
	public URIReference(ASN1Encodable uriRefEncodable)
		throws IOException
	{
		if(uriRefEncodable instanceof ASN1Sequence)
		{
			ASN1Encodable[] uriRef = ((ASN1Sequence) uriRefEncodable).toArray();

			// if the URIReference has a hashAlgorithm it must also have a hashValue.
			// if it has one without the other throw an exception
			if(uriRef.length == 2)
			{
				throw new IOException("Attempt to parse invalid UriReference - contains hashAlgorithm, but no hashValue - must have both or neither!"); 
			}
			
			// get the first field, uriRefId
			if(uriRef.length > 0 && uriRef[0] != null)
			{
				if(uriRef[0] instanceof DERIA5String)
				{
					_uriRefId = (DERIA5String) uriRef[0];
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing URIReference.uriRefId. Expected type DERIA5String; Found " 
									+ uriRef[0].getClass().toString());
				}
			}

			if(uriRef.length > 1 && uriRef[1] != null)
			{
				// get the second field, _hashAlgorithm
//				if(uriRef[1] instanceof AlgorithmIdentifier)
//				{
//					_hashAlgorithm = (AlgorithmIdentifier) uriRef[1];
//				}
//				else if(uriRef[1] instanceof ASN1ObjectIdentifier)
//				{
//					// hashAlghorithm should be encoded as an AlgorithmIdentifier but we will tolerate an ASN1ObjectIdentifier
//					_hashAlgorithm = new AlgorithmIdentifier((ASN1ObjectIdentifier) uriRef[1]);
//				}
//				else {
//					// unexpected type
//					throw new IOException(
//							"Unexpected ASN1 formatting while parsing URIReference.hashAlgorithm. Expected type AlgorithmIdentifier; Found " 
//									+ uriRef[1].getClass().toString());
//				}
			    
                if (uriRef[1] instanceof ASN1Sequence) {
                    ASN1Encodable[] algorithmIdentifier_array = ((ASN1Sequence) uriRef[1]).toArray();
                    if (algorithmIdentifier_array.length > 0 && algorithmIdentifier_array[0] != null) 
                    {
                        if (algorithmIdentifier_array[0] instanceof ASN1ObjectIdentifier) 
                        {
                            _hashAlgorithm = new AlgorithmIdentifier((ASN1ObjectIdentifier) algorithmIdentifier_array[0]);
                        } 
                        else {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing URIReference.hashAlgorithm.algorithm. Expected type ASN1ObjectIdentifier; Found "
                                            + algorithmIdentifier_array[0].getClass().toString());
                        }
                    }
                }
			    else {
                    // unexpected type
                    throw new IOException(
                            "Unexpected ASN1 formatting while parsing URIReference.hashAlgorithm. Expected type ASN1Sequence; Found " 
                                    + uriRef[1].getClass().toString());
			    }


				// get the third field, _hashValue
				if(uriRef[2] instanceof DERBitString)
				{
					_hashValue = (DERBitString) uriRef[2];
				}
				else if(uriRef[2] instanceof ASN1BitString)
				{
					// hashValue should be encoded as an DERBitString but we will tolerate an ASN1BitString
					_hashValue = new DERBitString(((ASN1BitString) uriRef[2]).getBytes()); 
				}
				else {
					// unexpected type
					throw new IOException(
							"Unexpected ASN1 formatting while parsing URIReference.hashValue. Expected type DERBitString; Found " 
									+ uriRef[2].getClass().toString());
				}

			}
		}		
		else {
			// unexpected type
			throw new IOException(
					"Unexpected ASN1 formatting while parsing URIReference. Expected ASN1Sequence type; Found " 
							+ uriRefEncodable.getClass().toString());
		}
	}

	
	
	/* (non-Javadoc)
	 * Return the ASN1 encoded object containing a URIReference
	 * 
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1Encodable[] uriReference;
		if(_hashAlgorithm != null) {
			// must have both _hashAlgorithm and _hashValue
			uriReference = new ASN1Encodable[3];
			uriReference[0] = _uriRefId;
			uriReference[1] = _hashAlgorithm;
			uriReference[2] = _hashValue;
			
		}
		else {
			// uniformResourceIdentifier is required
			uriReference = new ASN1Encodable[1];
			uriReference[0] = _uriRefId;
		}		

		return new DLSequence(uriReference);
	}



	/**
	 * @return the uniformResourceIdentifier
	 */
	public DERIA5String getUniformResourceIdentifier() {
		return _uriRefId;
	}



	/**
	 * @param _uriRefId the _uriRefId to set
	 */
	public void setUniformResourceIdentifier(DERIA5String _uriRefId) {
		this._uriRefId = _uriRefId;
	}



	/**
	 * @return the _hashAlgorithm
	 */
	public AlgorithmIdentifier getHashAlgorithm() {
		return _hashAlgorithm;
	}



	/**
	 * @param _hashAlgorithm the _hashAlgorithm to set
	 */
	public void setHashAlgorithm(AlgorithmIdentifier _hashAlgorithm) {
		this._hashAlgorithm = _hashAlgorithm;
	}



	/**
	 * @return the _hashValue
	 */
	public DERBitString getHashValue() {
		return _hashValue;
	}



	/**
	 * @param _hashValue the _hashValue to set
	 */
	public void setHashValue(DERBitString _hashValue) {
		this._hashValue = _hashValue;
	}
}
