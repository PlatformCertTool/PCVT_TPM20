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

import java.io.IOException;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * @author admin
 *
 */
public class X509ToPem {

	/**
	 * 
	 */
	public X509ToPem() {
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if(args.length != 2)
		{
			output_usage();
			System.exit(1);
		}
	
		String infilename = args[0];
		String outfilename= args[1];
		
		X509CertificateHolder cert;
		try {
			cert = new X509CertificateHolder(TP_FileUtils.readBinaryFile(infilename, true));
			TP_FileUtils.writePemFile("X509 CERTIFICATE", cert.getEncoded(), outfilename, true);
			System.exit(0);
		} catch (IOException e) {
			System.out.println("ERROR: " + e.getLocalizedMessage());
			System.exit(1);
		}
		
	}

	private static void output_usage()
	{
		final String usage = 
				"\nThis application converts an input X.509 Certificate from DER format to PEM format" +
				"\nUSAGE: \n  X509ToPem <input_file> <output_file> \n" +
						 "\n      <input_file>  input X.509 Certificate in DER (binary) format" +
						 "\n      <output_file> filename where the ouput x.509 Certificate will be written in PEM format"; 
		
		System.out.println(usage);
	}
}
