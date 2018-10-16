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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

/**
 *    ASN.1 structure.
 *    
 * ComponentIdentifier ::= SEQUENCE {
 *     componentManufacturer UTF8String (SIZE (1..STRMAX)),
 *     componentModel UTF8String (SIZE (1..STRMAX)),
 *     componentSerial[0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     componentRevision [1] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     componentManufacturerId [2] IMPLICIT PrivateEnterpriseNumber OPTIONAL,
 *     fieldReplaceable [3] IMPLICIT BOOLEAN OPTIONAL,
 *     componentAddress [4] IMPLICIT SEQUENCE(SIZE(1..CONFIGMAX)) OF ComponentAddress OPTIONAL }
 *
 *     ComponentAddress ::= SEQUENCE {
 *     addressType AddressType,
 *     addressValue UTF8String (SIZE (1..STRMAX)) }
 *
 *     AddressType ::= OBJECT IDENTIFIER (
 *          tcg-address-ethernetmac | tcg-address-wlanmac | tcg-address-bluetoothmac)
 *
 *     PrivateEnterpriseNumber OBJECT IDENTIFIER :: = { enterprise private-enterprise-number }
 *   
 *
 *
 */
public class ComponentIdentifier extends Asn1Translator {
    private String                 componentManufacturer=null;
    private String                 componentModel=null;
    private String                 componentSerial=null;
    private String                 componentRevision=null;
    private ASN1ObjectIdentifier   componentManufacturerId=null;
    private Boolean                fieldReplaceable = null;
    private ComponentAddress[]     componentAddress; 
    
    /**
     * Create an empty ComponentIdentifier
     */
    public ComponentIdentifier() {
    }
    
    /**
     * Create an empty ComponentIdentifier
     */
    public ComponentIdentifier(String componentManufacturer,
                               String componentModel,
                               String componentSerial,
                               String componentRevision,
                               ASN1ObjectIdentifier componentManufactuerId,
                               Boolean fieldReplaceable,
                               ComponentAddress[] componentAddress) 
    {
        this.componentManufacturer = componentManufacturer;
        this.componentModel = componentModel;
        this.componentSerial = componentSerial;
        this.componentRevision = componentRevision;
        this.componentManufacturerId = componentManufactuerId;
        this.fieldReplaceable = fieldReplaceable;
        this.componentAddress = componentAddress;
    }

    /**
     * Create a ComponentIdentifier from an ASN1Sequence.
     * The ASN1Sequence should be formatted correctly and contain the correct information.
     * If it is missing information it is not assigned.  If an unexpected format is encountered
     * an IOException is thrown.
     * 
     * The expected format is:
     * 
     *  ASN1Sequence
     *      componentManufacturer        DERUTF8String
     *      componentModel               DERUTF8String
     *      componentSerial              TAGGED 0 DERUTF8String OPTIONAL
     *      componentRevision            TAGGED 1 DERUTF8String OPTIONAL
     *      componentManufactuerId       TAGGED 2 ASN1ObjectIdentifier OPTIONAL
     *      fieldReplaceable             TAGGED 3 ASN1Boolean OPTIONAL
     *      componentAddress             TAGGED 4 ASN1Sequence OPTIONAL    
     * 
     * @param componentIdentifierEncodable
     * @throws IOException if unexpected ASN1 formatting is encountered
     */
    public ComponentIdentifier(ASN1Encodable componentIdentifierEncodable) 
        throws IOException
    {
        if(componentIdentifierEncodable instanceof ASN1Sequence)
        {
            ASN1Encodable[] componentIdentifier_array = ((ASN1Sequence) componentIdentifierEncodable).toArray();
            int componentIdentifierIdx = 0;

            // the first 2 fields are mandatory
            if(componentIdentifier_array.length > 0)
            {
                if(componentIdentifier_array[0] instanceof DERUTF8String)
                {
                    this.componentManufacturer = ((DERUTF8String)componentIdentifier_array[0]).getString();
                    componentIdentifierIdx++;
                }
                else
                {
                    // unexpected type
                    throw new IOException(
                            "Unexpected ASN1 formatting while parsing ComponentIdentifier.componentManufacturer. Expected DERUTF8String; Found " 
                                    + componentIdentifier_array[0].getClass().toString());
                }
            }            
            if(componentIdentifier_array.length > 1)
            {
                if(componentIdentifier_array[0] instanceof DERUTF8String)
                {
                    this.componentModel = ((DERUTF8String)componentIdentifier_array[1]).getString();
                    componentIdentifierIdx++;
                }
                else
                {
                    // unexpected type
                    throw new IOException(
                            "Unexpected ASN1 formatting while parsing ComponentIdentifier.componentModel. Expected DERUTF8String; Found " 
                                    + componentIdentifier_array[1].getClass().toString());
                }
            }

            // Next 5 fields are optional ASN1 Tagged fields - loop through them
            int maxTaggedObjectIndex = componentIdentifierIdx + 5; // 3 if there is was no version field, 4 if there was
            for(; componentIdentifierIdx < maxTaggedObjectIndex && componentIdentifierIdx < componentIdentifier_array.length; 
                    componentIdentifierIdx++)
            {
                if(componentIdentifier_array[componentIdentifierIdx] instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject taggedObj = (ASN1TaggedObject) componentIdentifier_array[componentIdentifierIdx];
                    int saElemTag = taggedObj.getTagNo();
                    if(saElemTag == 0) // componentSerial
                    {
                        if(taggedObj.getObject() instanceof DERUTF8String)
                        {
                            this.componentSerial = ((DERUTF8String) taggedObj.getObject()).getString();
                        }
                        else if (taggedObj.getObject() instanceof DEROctetString) 
                        {
                            this.componentSerial = DERUTF8String.getInstance(taggedObj, false).getString();
                        } 
                        else {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing ComponentIdentifier.componentSerial. "
                                    + "Expected DERUTF8String or DEROctetString; Found " 
                                    + taggedObj.getObject().getClass().toString());
                        }
                    }
                    else if(saElemTag == 1) // componentRevision
                    {
                        if (taggedObj.getObject() instanceof DERUTF8String)
                        {
                            this.componentRevision = ((DERUTF8String) taggedObj.getObject()).getString();
                        }
                        else if(taggedObj.getObject() instanceof DEROctetString)
                        {
                            this.componentRevision = DERUTF8String.getInstance(taggedObj, false).getString();
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing ComponentIdentifier.componentRevision. "
                                    + "Expected DERUTF8String or DEROctetString; Found " 
                                            + taggedObj.getObject().getClass().toString());
                        }
                    }
                    else if(saElemTag == 2) // componentManufacturerId
                    {
                        if (taggedObj.getObject() instanceof ASN1ObjectIdentifier) {
                            
                            this.componentManufacturerId = (ASN1ObjectIdentifier) taggedObj.getObject();
                        }
                        else if(taggedObj.getObject() instanceof DEROctetString)
                        {
                            this.componentManufacturerId = ASN1ObjectIdentifier.getInstance(taggedObj, false);
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing ComponentIdentifier.componentManufacturerId. "
                                    + "Expected ASN1ObjectIdentifier or DEROctetString; Found " 
                                            + taggedObj.getObject().getClass().toString());
                        }
                    }
                    else if(saElemTag == 3) // fieldReplaceable
                    {
                        if(taggedObj.getObject() instanceof ASN1Boolean)
                        {
                            this.fieldReplaceable = new Boolean(((ASN1Boolean)taggedObj.getObject()).isTrue());
                        }
                        else if (taggedObj.getObject() instanceof DEROctetString)
                        {
                            this.fieldReplaceable = new Boolean (ASN1Boolean.getInstance(taggedObj, false).isTrue());
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing ComponentIdentifier.fieldReplaceable. "
                                    + "Expected ASN1Boolean or DEROctetString; Found " 
                                            + taggedObj.getObject().getClass().toString());
                        }
                    }
                    else if(saElemTag == 4) // componentAddress
                    {
                        if(taggedObj.getObject() instanceof ASN1Sequence)
                        {
                            ASN1Encodable[] componentAddress_array = ((ASN1Sequence) taggedObj.getObject()).toArray();
                            
                            if (componentAddress_array.length > 0 && componentAddress_array[0] instanceof ASN1Sequence)
                            {
                                // more than one component addresses
                                this.componentAddress = new ComponentAddress[componentAddress_array.length];
                                
                                for (int i = 0; i < componentAddress_array.length; i++)
                                {                                 
                                     this.componentAddress[i] = new ComponentAddress(componentAddress_array[i]);
                                }
                            }
                            else
                            {
                                // only one component addresses
                                this.componentAddress = new ComponentAddress[1];
                                this.componentAddress[0] = new ComponentAddress((ASN1Sequence) taggedObj.getObject());  
                            }                
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing ComponentIdentifier.componentAddress[]. Expected ASN1Sequence; Found " 
                                            + taggedObj.getObject().getClass().toString());
                        }                       
                    }
                }
                else
                {
                    // no more optional tagged objects
                    break;
                }
            }       
        }
        else {
            // unexpected type
            throw new IOException(
                    "Unexpected ASN1 formatting while parsing ComponentIdentifier. Expected ASN1Sequence type; Found " 
                            + componentIdentifierEncodable.getClass().toString());
        }
    }
    
    /**
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector componentIdentifierArray = new ASN1EncodableVector();
        
        if(componentManufacturer != null)
        {
            componentIdentifierArray.add(new DERUTF8String(componentManufacturer));
        }

        if(componentModel != null)
        {
            componentIdentifierArray.add(new DERUTF8String(componentModel));
        }
        
        if(componentSerial != null)
        {
            componentIdentifierArray.add(new DERTaggedObject(false, 0, new DERUTF8String(componentSerial)));
        }
        
        if(componentRevision != null)
        {
            componentIdentifierArray.add(new DERTaggedObject(false, 1, new DERUTF8String(componentRevision)));
        }
        
        if(componentManufacturerId != null)
        {
            componentIdentifierArray.add(new DERTaggedObject(false, 2, componentManufacturerId));
        }
        
        if(fieldReplaceable != null)
        {
            componentIdentifierArray.add(new DERTaggedObject(false, 3, 
                        ASN1Boolean.getInstance(fieldReplaceable.booleanValue())));
        }
        if(componentAddress != null && componentAddress.length > 0)
        {
            componentIdentifierArray.add(new DERTaggedObject(false, 4, new DERSequence(componentAddress)));
        }
        
        return new DERSequence(componentIdentifierArray);
    }

    /**
     * @return the componentManufacturer
     */
    public String getComponentManufacturer() {
        return componentManufacturer;
    }

    /**
     * @param componentManufacturer the componentManufacturer to set
     */
    public void setComponentManufacturer(String componentManufacturer) {
        this.componentManufacturer = componentManufacturer;
    }

    /**
     * @return the componentModel
     */
    public String getComponentModel() {
        return componentModel;
    }

    /**
     * @param componentModel the componentModel to set
     */
    public void setComponentModel(String componentModel) {
        this.componentModel = componentModel;
    }

    /**
     * @return the componentSerial
     */
    public String getComponentSerial() {
        return componentSerial;
    }

    /**
     * @param componentSerial the componentSerial to set
     */
    public void setComponentSerial(String componentSerial) {
        this.componentSerial = componentSerial;
    }

    /**
     * @return the componentRevision
     */
    public String getComponentRevision() {
        return componentRevision;
    }

    /**
     * @param componentRevision the componentRevision to set
     */
    public void setComponentRevision(String componentRevision) {
        this.componentRevision = componentRevision;
    }

    /**
     * @return the componentManufacturerId
     */
    public ASN1ObjectIdentifier getComponentManufacturerId() {
        return componentManufacturerId;
    }

    /**
     * @param componentManufacturerId the componentManufacturerId to set
     */
    public void setComponentManufacturerId(ASN1ObjectIdentifier componentManufacturerId) {
        this.componentManufacturerId = componentManufacturerId;
    }

    /**
     * @return the fieldReplaceable
     */
    public Boolean getFieldReplaceable() {
        return fieldReplaceable;
    }

    /**
     * @param fieldReplaceable the fieldReplaceable to set
     */
    public void setFieldReplaceable(Boolean fieldReplaceable) {
        this.fieldReplaceable = fieldReplaceable;
    }

    /**
     * @return the componentAddress
     */
    public ComponentAddress[] getComponentAddress() {
        return componentAddress;
    }

    /**
     * @param componentAddress the componentAddress to set
     */
    public void setComponentAddress(ComponentAddress[] componentAddress) {
        this.componentAddress = componentAddress;
    }

}
