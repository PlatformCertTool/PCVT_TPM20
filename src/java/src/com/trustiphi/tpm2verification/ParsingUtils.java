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

package com.trustiphi.tpm2verification;

import org.bouncycastle.asn1.x509.GeneralName;

/**
 * General Utilities to help 
 *
 */
public class ParsingUtils {
	/**
	 * @see @org.bouncycastle.asn1.x509.GeneralName
	 * @see @getGeneralNameTagStringValue
	 * 
	 * @param tag_string string value representing the GenaralName tag 
	 * @return the defined int value of the corresponding tag
	 */
	public static int getGeneralNameTagIntValue(String tag_string) 
			throws IllegalArgumentException
	{
		switch(tag_string)
		{
		case "otherName":
		case "0":
		case "other_name":
			return GeneralName.otherName;
			
		case "rfc822Name":
		case "1":
			return GeneralName.rfc822Name;
			
		case "dNSName":
		case "2":
		case "dns_name":
			return GeneralName.dNSName;
			
		case "x400Address":
		case "3":
			return GeneralName.x400Address;
			
		case "directoryName":
		case "4":
		case "directory_name":
			return GeneralName.directoryName;
			
		case "ediPartyName":
		case "5":
		case "edi_party_name":
			return GeneralName.ediPartyName;
			
		case "uniformResourceIdentifier":
		case "6":
		case "uri":
			return GeneralName.uniformResourceIdentifier;
			
		case "iPAddress":
		case "7":
		case "ip_address":
			return GeneralName.iPAddress;
			
		case "registeredID":
		case "8":
		case "registered_id":
			return GeneralName.registeredID;
			
		default:
			throw new IllegalArgumentException("Unrecognized GenaralNameTag String value!");
		}
	}

	/**
	 * @see @org.bouncycastle.asn1.x509.GeneralName
	 * @see @getGeneralNameTagIntValue
	 * 
	 * @param tag_int int value representing the GenaralName tag 
	 * @return string value of corresponding GenaralName tag
	 */
	public static String getGeneralNameTagStringValue(int tag_int)
			throws IllegalArgumentException
	{
		switch(tag_int)
		{
		case GeneralName.otherName:
			return "otherName";
			
		case GeneralName.rfc822Name:
			return "rfc822Name";
			
		case GeneralName.dNSName:
			return "dNSName";
			
		case GeneralName.x400Address:
			return "x400Address";
			
		case GeneralName.directoryName:
			return "directoryName";
			
		case GeneralName.ediPartyName:
			return "ediPartyName";
			
		case GeneralName.uniformResourceIdentifier:
			return "uniformResourceIdentifier";
			
		case GeneralName.iPAddress:
			return "iPAddress";
			
		case GeneralName.registeredID:
			return "registeredID";
			
		default:
			throw new IllegalArgumentException("Unrecognized GenaralNameTag value!");
		}
	}

}
