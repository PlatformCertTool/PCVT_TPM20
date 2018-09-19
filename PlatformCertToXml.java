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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Security;

import javax.xml.bind.JAXBException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author admin
 *
 */
public class PlatformCertToXml {
	public static final String PARAMATER_PLATFORM_CERT_FILENAME = "-f";
	public static final String PARAMATER_OUTPUT_FILENAME        = "-o";
	public static final String PARAMATER_VERBOSE                = "-v";
	public static final String PARAMATER_INPUT_FORMAT_DER      = "-der";

	private static String  platformCertFilename=null;
	private static String  outputFilename=null;
	private static boolean verbose=false; // default to non-verbose
	private static boolean pemIn=true;    // default to input in PEM format
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		if(!parseArguments(args))
		{
			output_usage();
			System.exit(1);
		}

		boolean valid = process();
		
		System.exit(valid? 0: 1);
	}

	private static boolean process()
	{
		boolean wasProcessedSuccessfully = false;
		
		PlatformCertificateHolder platformCertificateHolder = new PlatformCertificateHolder();
		
		boolean platfomCertLoaded = false;
		if(pemIn)
		{
			try {
				platformCertificateHolder.loadFromFilePEM(new File(platformCertFilename));
				platfomCertLoaded = true;
			} 
			catch (FileNotFoundException e) {
				// Can't find file so we're done -
				//   but this shoudn't happen because this should have been tested for already.
				System.out.println("ERROR: Can't find Platform Certificate file!\n" + e.getLocalizedMessage());
				return false;
			} 
			catch (IOException e) {
				System.out.println("WARNING: Failed parsing Platform Certificate file as PEM formatted file! (Will attempt to parse as DER.)\n");
			}
		}
		
		if(!platfomCertLoaded)
		{
			try {
				platformCertificateHolder.loadFromFileDER(new File(platformCertFilename));
				platfomCertLoaded = true;
			} 
			catch (FileNotFoundException e) {
				// Can't find file so we're done -
				//   but this really shoudn't happen because this was tested for already.
				System.out.println("ERROR: Can't find Platform Certificate file!\n" + e.getLocalizedMessage());
				return false;
			} 
			catch (IOException e) {
				System.out.println("ERROR: Failed parsing Platform Certificate file as DER formatted file!\n" + e.getLocalizedMessage());
			}
		}
		
		if(platfomCertLoaded)
		{
			FileOutputStream outputFilestream;
			try 
			{
				outputFilestream = new FileOutputStream(new File(outputFilename));
				PlatformCertificateManager.writeToXML(platformCertificateHolder, outputFilestream);
				wasProcessedSuccessfully = true;
				System.out.println("Output XML-formatted Platform Certificate information to file " + outputFilename);
			} 
			catch (FileNotFoundException e) {
				System.out.println("ERROR: Failed to create/find output file!\n" + e.getLocalizedMessage());
			} 
			catch (JAXBException e) {
				System.out.println("ERROR: Failed to output XML representation of the Platform Certificate!\n" + e.getLocalizedMessage());
				e.printStackTrace();
			}
		}
		
		return wasProcessedSuccessfully;
	}

	private static boolean parseArguments(String[] args)
	{
		for(String arg: args)
		{
			if(arg.contains("="))
			{
				String[] parameter = arg.split("=");
				if(parameter.length > 0)
				{
					if(parameter.length < 2)
					{
						System.out.println("Found command-line parameter " + parameter[0] + " with missing value! Ignoring paramater.");
						continue;
					}
					
					if(parameter[0].equals(PARAMATER_PLATFORM_CERT_FILENAME))
					{
						platformCertFilename = parameter[1];
					}
					else if(parameter[0].equals(PARAMATER_OUTPUT_FILENAME))
					{
						outputFilename = parameter[1];
					}
				}
			}
			else if(arg.equals(PARAMATER_VERBOSE)){
				verbose = true;
			}
			else if(arg.equals(PARAMATER_INPUT_FORMAT_DER))
			{
				pemIn = false;
			}
		}
		
		if(verbose)
		{
			System.out.println("Platform Certificate File: " + platformCertFilename);
			System.out.println("Output Filename: " + outputFilename);
			System.out.println("Verbose Mode: " + verbose);
			if(!pemIn)
			{
				System.out.println("Input Platform Certificate is DER formatted.");
			}
		}
		
		return argsAreValid();
	}

	private static boolean argsAreValid()
	{
		if(platformCertFilename != null)
		{
			platformCertFilename  = TP_FileUtils.validateFile(platformCertFilename, verbose);
		}
		else {
			System.out.println("ERROR: Missing Platform Certificate file command line argument (" + PARAMATER_PLATFORM_CERT_FILENAME + ")!");
			return false;
		}
		
		if(platformCertFilename == null)
		{
			System.out.println("ERROR: Can't find Platform Certificate file!");
			return false;
		}

		if(outputFilename == null || outputFilename.length() <= 0)
		{
			System.out.println("ERROR: Missing output file argument (" + PARAMATER_OUTPUT_FILENAME + ")!");
			return false;
		}
		
		return true;
	}		
	
	private static void output_usage()
	{
		final String usage = 
				"\nUSAGE: \n PlatformCertToXml " +
						PARAMATER_PLATFORM_CERT_FILENAME + "=<PlatformCertificate file> " +
						PARAMATER_OUTPUT_FILENAME +"=<output file> " + 
						"[" + PARAMATER_VERBOSE +"] " + 
						"[" + PARAMATER_INPUT_FORMAT_DER +"]\n\n" + 
						"Note: do not include space before or after the '=' in specifying command line arguments.\n" + 
						PARAMATER_PLATFORM_CERT_FILENAME + "   Platform Certificate file - could be in PEM or DER format. If '" + PARAMATER_INPUT_FORMAT_DER + "' is not used an attempt is first made to parse as PEM and if that fails it is parsed as DER.\n" +
						PARAMATER_OUTPUT_FILENAME +"   output file (XML formatted) - on success will contain the information in the input Platform Certificate.\n" + 
						PARAMATER_INPUT_FORMAT_DER  + " Skip attempt to parse as a PEM file - only parse as a DER.\n" +
						PARAMATER_VERBOSE + "   Verbose mode";
		
		System.out.println(usage);
	}
}
