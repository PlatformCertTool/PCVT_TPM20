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


/******
 * Base class for ASN1 objects with complex structures that are needed by the TPM Verification Tool Set 
 * but are not defined in the Bouncy Castle library.
 * The subclasses will be used to more easily set values in Java and create the (Bouncy Castle) ASN1 structure
 * of the object. 
 */

package com.trustiphi.asn1;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * @author admin
 *
 */
public abstract class Asn1Translator implements ASN1Encodable {
	
}
