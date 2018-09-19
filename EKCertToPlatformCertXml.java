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
*
* Initial Development by TrustPhi, LLC, www.trusiphi.com
*/

package com.trustiphi.tpm2verification;

import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.bouncycastle.cert.AttributeCertificateHolder;

import com.trustiphi.asn1.EndorsementKeyCertificateHolder;

/**
 * @author admin
 *
 */
public class EKCertToPlatformCertXml {

	/**
	 * 
	 */
	public EKCertToPlatformCertXml() {		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if(args.length < 2)
		{
			output_usage();
			System.exit(1);
		}
	
		String infilename = args[0];
		String outfilename= args[1];
		
		try {
			EndorsementKeyCertificateHolder ekCert = EndorsementKeyCertificateHolder.loadInstance(infilename);
			PlatformCertificateHolder platformCert = new PlatformCertificateHolder();
			platformCert.setHolder(new AttributeCertificateHolder(ekCert.getIssuer(), ekCert.getSerialNumber()));

			PlatformCertificateManager.writeToXML(platformCert, new FileOutputStream(outfilename)); 
			System.out.println("Wrote XML file to " + outfilename);
			System.exit(0);
		} catch (IOException e) {
			System.out.println("ERROR: " + e.getLocalizedMessage());
			System.exit(1);
		} catch (JAXBException e) {
			System.out.println("ERROR: " + e.getLocalizedMessage());
			System.exit(1);
		}
	}

	private static void output_usage()
	{
		final String usage = 
				"\nThis application parses an input Endorsement Key X.509 Certificate and outputs the Issuer and Serial Number information to a Platform Certificate XML formated file" +
				"\nUSAGE: \n  EKCertToPlatformCertXml <input_file> <output_file> \n" +
						 "\n      <input_file>  input EK X.509 Certificate in DER (binary) or PEM format" +
						 "\n      <output_file> filename where the ouput Platform Certificate XML file will be written"; 
		
		System.out.println(usage);
	}
}
