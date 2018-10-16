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
import java.util.ArrayList;
import java.util.List;

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
 * ManufacturerId ::= SEQUENCE {
 *     manufacturerIdentifier PrivateEnterpriseNumber
 *  }
 *
 * PrivateEnterpriseNumber OBJECT IDENTIFIER :: = { enterprise private-enterprise-number }
 * 
 * All assigened private enterprise numbers are listed at the Internet Assigned Numbers
 * Authority (IANA) web site.
 * 
 */
public class ManufacturerId extends Asn1Translator {
    private List<String> manufacturer_id_list=new ArrayList<>();

	/**
	 * 
	 */
	public ManufacturerId() {
		
		
	}
	public ManufacturerId(String manufacturer_identifier) {
		manufacturer_id_list.add(manufacturer_identifier);
	}
	
	public ManufacturerId(ASN1ObjectIdentifier manufacturer_identifier) {
		manufacturer_id_list.add(manufacturer_identifier.getId());
	}
	
	public void add(String manufacturer_identifier) {
		manufacturer_id_list.add(manufacturer_identifier);
	}
	
	public void add(ASN1ObjectIdentifier manufacturer_identifier) {
		manufacturer_id_list.add(manufacturer_identifier.getId());
	}
	
	public ManufacturerId(ASN1Encodable manufacturerIdEncodable) throws IOException {
        if(manufacturerIdEncodable instanceof ASN1Sequence)
        {
            ASN1Sequence propertiesSeq = (ASN1Sequence) manufacturerIdEncodable;
            ASN1Encodable[] manuId_array = propertiesSeq.toArray();
            for(ASN1Encodable manuId: manuId_array)
            {
            	if(manuId instanceof ASN1ObjectIdentifier)
            	{
            		manufacturer_id_list.add(((ASN1ObjectIdentifier) manuId).getId());
            	}
            	else if(manuId instanceof DERUTF8String)
            	{
            		manufacturer_id_list.add(((DERUTF8String) manuId).toString());
            	}
            }
        }
        else if(manufacturerIdEncodable instanceof ASN1ObjectIdentifier)
        {
    		manufacturer_id_list.add(((ASN1ObjectIdentifier) manufacturerIdEncodable).getId());
        }        
        else if(manufacturerIdEncodable instanceof DERUTF8String)
        {
    		manufacturer_id_list.add(((DERUTF8String) manufacturerIdEncodable).toString());
        }   
        else {
            // unexpected type
            throw new IOException(
                    "Unexpected ASN1 formatting while parsing ManufacturerId. Expected ASN1Seqeunce; Found " 
                            + manufacturerIdEncodable.getClass().toString());
        }
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1Encodable[] asn1EncodableArr = new ASN1Encodable[manufacturer_id_list.size()];
        for(int i=0; i < manufacturer_id_list.size(); i++)
        {
        	asn1EncodableArr[i] = new ASN1ObjectIdentifier(manufacturer_id_list.get(i));
        }
        
        DLSequence asn1_menufacturer_id = new DLSequence(asn1EncodableArr);

        return asn1_menufacturer_id;
	}
	/**
	 * @return the manufacturer_id_list
	 */
	public List<String> getManufacturerIdList() {
		return manufacturer_id_list;
	}

}
