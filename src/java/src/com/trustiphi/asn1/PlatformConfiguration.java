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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * platformConfiguration ATTRIBUTE ::= {
 *      WITH SYNTAX PlatformConfiguration   
 *      ID tcg-at-platformConfiguration-v1
 *  }
 *  
 *  PlatformConfiguration ::= SEQUENCE {
 *      componentIdentifier [0] IMPLICIT SEQUENCE(SIZE(1..CONFIGMAX)) OF ComponentIdentifier OPTIONAL,
 *      platformProperties [1] IMPLICIT SEQUENCE(SIZE(1..CONFIGMAX)) OF Properties OPTIONAL,
 *      platformPropertiesUri [2] IMPLICIT URIReference OPTIONAL
 *  }
 *  
 *  ComponentIdentifier ::= SEQUENCE {
 *      componentManufacturer UTF8String (SIZE (1..STRMAX)),
 *      componentModel UTF8String (SIZE (1..STRMAX)),
 *      componentSerial[0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *      componentRevision [1] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *      componentManufacturerId [2] IMPLICIT PrivateEnterpriseNumber OPTIONAL,
 *      fieldReplaceable [3] IMPLICIT BOOLEAN OPTIONAL,
 *      componentAddress [4] IMPLICIT SEQUENCE(SIZE(1..CONFIGMAX)) OF ComponentAddress OPTIONAL }
 *  
 *  ComponentAddress ::= SEQUENCE {
 *      addressType AddressType,
 *      addressValue UTF8String (SIZE (1..STRMAX)) }
 *  
 *  AddressType ::= OBJECT IDENTIFIER (tcg-address-ethernetmac | tcg-address-wlanmac | tcg-address-bluetoothmac)
 *  
 *  Properties ::= SEQUENCE {
 *      propertyName UTF8String (SIZE (1..STRMAX)),
 *      propertyValue UTF8String (SIZE (1..STRMAX)) }
 *
 * 
 */
public class PlatformConfiguration extends Asn1Translator {
    private ComponentIdentifier[] componentIdentifier = null;
    private Properties[] platformProperties = null;
    private URIReference platformPropertiesUri = null;
    
    /**
     * Create an empty PlatformConfiguration
     */
    public PlatformConfiguration() {
    }
    
    /**
     * Create an PlatformConfiguration with input values
     */
    public PlatformConfiguration(ComponentIdentifier[] componentIdentifier,
                                 Properties[] platformProperties,
                                 URIReference platformPropertiesUri) {
        this.componentIdentifier = componentIdentifier;
        this.platformProperties = platformProperties;
        this.platformPropertiesUri = platformPropertiesUri;
    }
    
    /**
     * Create a PlatformConfiguration from an ASN1Sequence.
     * The ASN1Sequence should be formatted correctly and contain the correct information.
     * If it is missing information it is not assigned.  If an unexpected format is encountered
     * an IOException is thrown.
     * 
     * The expected format is:
     * 
     *  ASN1Sequence
     *      componentIdentifier             TAGGED 0 ASN1Sequence OPTIONAL
     *      platformProperties              TAGGED 1 ASN1Sequence OPTIONAL
     *      platformPropertiesUri           TAGGED 2 ASN1Sequence OPTIONAL
     * 
     * @param platformConfigurationEncodable
     * @throws IOException if unexpected ASN1 formatting is encountered 
     */
    public PlatformConfiguration(ASN1Encodable platformConfigurationEncodable) 
            throws IOException 
    {
        if(platformConfigurationEncodable instanceof ASN1Sequence)
        {
            ASN1Encodable[] platformConfiguration_array = ((ASN1Sequence) platformConfigurationEncodable).toArray();
            int platformConfigurationIdx = 0;
            
            // Next 3 fields are optional ASN1 Tagged fields - loop through them
            int maxTaggedObjectIndex = platformConfigurationIdx + 3;
            for(; platformConfigurationIdx < maxTaggedObjectIndex && platformConfigurationIdx < platformConfiguration_array.length; 
                    platformConfigurationIdx++)
            {
                if(platformConfiguration_array[platformConfigurationIdx] instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject saTaggedObj = (ASN1TaggedObject) platformConfiguration_array[platformConfigurationIdx];
                    int saElemTag = saTaggedObj.getTagNo();
                    if(saElemTag == 0) // componentIdentifier
                    {
                        if(saTaggedObj.getObject() instanceof ASN1Sequence)
                        {
                            ASN1Encodable[] componentIdentifier_array = ((ASN1Sequence) saTaggedObj.getObject()).toArray();
                            
                            if (componentIdentifier_array.length > 0 && componentIdentifier_array[0] instanceof ASN1Sequence)
                            {
                                // more than one componentIdentifiers
                                this.componentIdentifier = new ComponentIdentifier[componentIdentifier_array.length];
                                
                                for (int i = 0; i < componentIdentifier_array.length; i++)
                                {                                 
                                     this.componentIdentifier[i] = new ComponentIdentifier(componentIdentifier_array[i]);
                                }
                            }
                            else if (componentIdentifier_array.length > 0)
                            {
                                // only one componentIdentifier
                                this.componentIdentifier = new ComponentIdentifier[1];
                                this.componentIdentifier[0] = new ComponentIdentifier((ASN1Sequence) saTaggedObj.getObject());                               
                            }                            
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing PlatformConfiguration.componentIdentifier[]. Expected ASN1Sequence; Found " 
                                            + saTaggedObj.getObject().getClass().toString());
                        }              
                    }
                    else if(saElemTag == 1) // platformProperties
                    {
                        if(saTaggedObj.getObject() instanceof ASN1Sequence)
                        {
                            ASN1Encodable[] platformProperties_array = ((ASN1Sequence) saTaggedObj.getObject()).toArray();
                            
                            if (platformProperties_array.length > 0 && platformProperties_array[0] instanceof ASN1Sequence)
                            {
                                // more than one platformProperties
                                this.platformProperties = new Properties[platformProperties_array.length];
                                
                                for (int i = 0; i < platformProperties_array.length; i++)
                                {                                 
                                     this.platformProperties[i] = new Properties(platformProperties_array[i]);
                                }
                            }
                            else
                            {
                                // only one platformProperties
                                this.platformProperties = new Properties[1];
                                this.platformProperties[0] = new Properties((ASN1Sequence) saTaggedObj.getObject());
                            }
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing PlatformConfiguration.platformProperties[]. Expected ASN1Sequence; Found " 
                                            + saTaggedObj.getObject().getClass().toString());
                        }   
                    }
                    else if(saElemTag == 2) // platformPropertiesUri
                    {
                        if(saTaggedObj.getObject() instanceof ASN1Sequence)
                        {
                            this.platformPropertiesUri = new URIReference(saTaggedObj.getObject());
                        }
                        if(saTaggedObj.getObject() instanceof DERIA5String)
                        {
							this.platformPropertiesUri = new URIReference((DERIA5String) saTaggedObj.getObject(), null, null);
                        }
                        else
                        {
                            // unexpected type
                            throw new IOException(
                                    "Unexpected ASN1 formatting while parsing PlatformConfiguration.platformPropertiesUri. Expected ASN1Sequence; Found " 
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
        }
        else {
            // unexpected type
            throw new IOException(
                    "Unexpected ASN1 formatting while parsing PlatformConfiguration. Expected ASN1Seqeunce; Found " 
                            + platformConfigurationEncodable.getClass().toString());
        }
    }
    
    /* (non-Javadoc)
     * 
     *  DLSequence
     *      componentIdentifier (ASN1Sequence)
     *      platformProperties (ASN1Sequence)
     *      platformPropertiesUri (ASN1Sequence)
     * 
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector platformConfigurationArray = new ASN1EncodableVector();
        
        if(componentIdentifier != null && componentIdentifier.length > 0)
        {
            platformConfigurationArray.add((new DERTaggedObject(false, 0, new DERSequence(componentIdentifier))));
        }
        
        if(platformProperties != null && platformProperties.length > 0)
        {
            platformConfigurationArray.add((new DERTaggedObject(false, 1, new DERSequence(platformProperties))));
        }
        if(platformPropertiesUri != null)
        {
            platformConfigurationArray.add((new DERTaggedObject(false, 2, platformPropertiesUri)));
        }
        
        return new DERSequence(platformConfigurationArray);
    }

    /**
     * @return the componentIdentifier
     */
    public ComponentIdentifier[] getComponentIdentifier() {
        return componentIdentifier;
    }

    /**
     * @param componentIdentifier the componentIdentifier to set
     */
    public void setComponentIdentifier(ComponentIdentifier[] componentIdentifier) {
        this.componentIdentifier = componentIdentifier;
    }

    /**
     * @return the platformProperties
     */
    public Properties[] getPlatformProperties() {
        return platformProperties;
    }

    /**
     * @param platformProperties the platformProperties to set
     */
    public void setPlatformProperties(Properties[] platformProperties) {
        this.platformProperties = platformProperties;
    }

    /**
     * @return the platformPropertiesUri
     */
    public URIReference getPlatformPropertiesUri() {
        return platformPropertiesUri;
    }

    /**
     * @param platformPropertiesUri the platformPropertiesUri to set
     */
    public void setPlatformPropertiesUri(URIReference platformPropertiesUri) {
        this.platformPropertiesUri = platformPropertiesUri;
    }

}
