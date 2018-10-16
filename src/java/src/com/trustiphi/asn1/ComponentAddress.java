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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;

/**
 *    ASN1 structure.
 * 
 * 
 * ComponentAddress ::= SEQUENCE {
 *     addressType AddressType,
 *     addressValue UTF8String (SIZE (1..STRMAX)) }
 *
 * AddressType ::= OBJECT IDENTIFIER (
 *    tcg-address-ethernetmac | tcg-address-wlanmac | tcg-address-bluetoothmac)
 *
 *
 * 
 */
public class ComponentAddress extends Asn1Translator {
    private ASN1ObjectIdentifier addressType=null;
    private String addressValue=null;
    
    /**
     * Create an empty ComponentAddress
     */
    public ComponentAddress() {
    }
    
    /**
     * Create an ComponentAddress with input values
     */
    public ComponentAddress(ASN1ObjectIdentifier addressType, String addressValue) {
        this.addressType = addressType;
        this.addressValue = addressValue;
    }
    
    /**
     * Create a ComponentAddress from an ASN1Sequence.
     * The ASN1Sequence should be formatted correctly and contain the correct information.
     * If it is missing information it is not assigned.  If an unexpected format is encountered
     * an IOException is thrown.
     * 
     * The expected format is:
     * 
     *  ASN1Sequence
     *      addressType (ASN1ObjectIdentifier)
     *      addressValue (DERUTF8String)
     * 
     * @param componentAddressEncodable
     * @throws IOException if unexpected ASN1 formatting is encountered 
     */
    public ComponentAddress(ASN1Encodable componentAddressEncodable) 
            throws IOException 
    {
        if(componentAddressEncodable instanceof ASN1Sequence)
        {
            ASN1Sequence componentAddressSeq = (ASN1Sequence) componentAddressEncodable;
            if(componentAddressSeq.size() > 0)
            {
                ASN1Encodable[] componentAddress_array = componentAddressSeq.toArray();
                if(componentAddress_array.length > 0)
                {
                    if(componentAddress_array[0] instanceof ASN1ObjectIdentifier)
                    {
                        this.addressType = (ASN1ObjectIdentifier) componentAddress_array[0]; 
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing ComponentAddress.addressType. Expected ASN1ObjectIdentifier; Found " 
                                        + componentAddress_array[0].getClass().toString());
                    }
                }
                if(componentAddress_array.length > 1)
                {
                    if(componentAddress_array[1] instanceof DERUTF8String)
                    {
                        this.addressValue = ((DERUTF8String)componentAddress_array[1]).getString();
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing ComponentAddress.addressValue. Expected DERUTF8String; Found " 
                                        + componentAddress_array[1].getClass().toString());
                    }
                }
            }            
        }
        else {
            // unexpected type
            throw new IOException(
                    "Unexpected ASN1 formatting while parsing ComponentAddress. Expected ASN1Seqeunce; Found " 
                            + componentAddressEncodable.getClass().toString());
        }
    }
    
    /* (non-Javadoc)
     * 
     *  DLSequence
     *      adressType (ASN1ObjectIdentifier)
     *      addressValue (DERUTF8String)
     * 
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1Encodable[] asn1EncodableArr = new ASN1Encodable[2];
        asn1EncodableArr[0] = asn1EncodableArr[1] = null;
        if(addressType != null) {
            asn1EncodableArr[0] = addressType;
        }
        if(addressValue != null) {
            asn1EncodableArr[1] = new DERUTF8String(addressValue);
        }
        DLSequence asn1_componentAddress = new DLSequence(asn1EncodableArr);

        return asn1_componentAddress;
    }

    /**
     * @return the addressType
     */
    public ASN1ObjectIdentifier getAddressType() {
        return addressType;
    }

    /**
     * @param addressType the addressType to set
     */
    public void setAddressType(ASN1ObjectIdentifier addressType) {
        this.addressType = addressType;
    }

    /**
     * @return the addressValue
     */
    public String getAddressValue() {
        return addressValue;
    }

    /**
     * @param addressValue the addressValue to set
     */
    public void setAddressValue(String addressValue) {
        this.addressValue = addressValue;
    }

}
