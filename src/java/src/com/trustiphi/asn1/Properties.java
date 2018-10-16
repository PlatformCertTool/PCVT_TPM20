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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;

/**
 *    ASN1 structure.
 * 
 * 
 * Properties ::= SEQUENCE {
 *     propertyName UTF8String (SIZE (1..STRMAX)),
 *     propertyValue UTF8String (SIZE (1..STRMAX)) }
 *
 *
 * 
 */
public class Properties extends Asn1Translator {
    private String propertyName=null;
    private String propertyValue=null;
    
    /**
     * Create an empty Properties
     */
    public Properties() {
    }
    
    /**
     * Create an Properties with input values
     */
    public Properties(String propertyName, String propertyValue) {
        this.propertyName = propertyName;
        this.propertyValue = propertyValue;
    }
    
    /**
     * Create a Properties from an ASN1Sequence.
     * The ASN1Sequence should be formatted correctly and contain the correct information.
     * If it is missing information it is not assigned.  If an unexpected format is encountered
     * an IOException is thrown.
     * 
     * The expected format is:
     * 
     *  ASN1Sequence
     *      propertyName (DERUTF8String)
     *      propertyValue (DERUTF8String)
     * 
     * @param propertiesEncodable
     * @throws IOException if unexpected ASN1 formatting is encountered 
     */
    public Properties(ASN1Encodable propertiesEncodable) 
            throws IOException 
    {
        if(propertiesEncodable instanceof ASN1Sequence)
        {
            ASN1Sequence propertiesSeq = (ASN1Sequence) propertiesEncodable;
            if(propertiesSeq.size() > 0)
            {
                ASN1Encodable[] properties_array = propertiesSeq.toArray();
                if(properties_array.length > 0)
                {
                    if(properties_array[0] instanceof DERUTF8String)
                    {
                        this.propertyName = ((DERUTF8String)properties_array[0]).getString();
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing Properties.propertyName. Expected DERUTF8String; Found " 
                                        + properties_array[0].getClass().toString());
                    }
                }
                if(properties_array.length > 1)
                {
                    if(properties_array[1] instanceof DERUTF8String)
                    {
                        this.propertyValue = ((DERUTF8String)properties_array[1]).getString();
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing Properties.propertyValue. Expected DERUTF8String; Found " 
                                        + properties_array[1].getClass().toString());
                    }
                }
            }            
        }
        else {
            // unexpected type
            throw new IOException(
                    "Unexpected ASN1 formatting while parsing Properties. Expected ASN1Seqeunce; Found " 
                            + propertiesEncodable.getClass().toString());
        }
    }
    
    /* (non-Javadoc)
     * 
     *  DLSequence
     *      propertyName (DERUTF8String)
     *      propertyValue (DERUTF8String)
     * 
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1Encodable[] asn1EncodableArr = new ASN1Encodable[2];
        asn1EncodableArr[0] = asn1EncodableArr[1] = null;
        if(propertyName != null) {
            asn1EncodableArr[0] = new DERUTF8String(propertyName);
        }
        if(propertyValue != null) {
            asn1EncodableArr[1] = new DERUTF8String(propertyValue);
        }
        DLSequence asn1_properties = new DLSequence(asn1EncodableArr);

        return asn1_properties;
    }

    /**
     * @return the propertyName
     */
    public String getPropertyName() {
        return propertyName;
    }

    /**
     * @param propertyName the propertyName to set
     */
    public void setPropertyName(String propertyName) {
        this.propertyName = propertyName;
    }

    /**
     * @return the propertyValue
     */
    public String getPropertyValue() {
        return propertyValue;
    }

    /**
     * @param propertyValue the propertyValue to set
     */
    public void setPropertyValue(String propertyValue) {
        this.propertyValue = propertyValue;
    }

}
