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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.xml.bind.JAXBException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.trustiphi.tpm2verification.platformcertparse.PlatformCertificateData;

/**
 * @author admin
 *
 */
public class PlatformCertFromXml {
	public static String defaultPrivateKeyString = 
			"MIIBOwIBAAJBAJv8ZpB5hEK7qxP9K3v43hUS5fGT4waKe7ix4Z4mu5UBv+cw7WSF" +
			"At0Vaag0sAbsPzU8Hhsrj/qPABvfB8asUwcCAwEAAQJAG0r3ezH35WFG1tGGaUOr" +
			"QA61cyaII53ZdgCR1IU8bx7AUevmkFtBf+aqMWusWVOWJvGu2r5VpHVAIl8nF6DS" +
			"kQIhAMjEJ3zVYa2/Mo4ey+iU9J9Vd+WoyXDQD4EEtwmyG1PpAiEAxuZlvhDIbbce" +
			"7o5BvOhnCZ2N7kYb1ZC57g3F+cbJyW8CIQCbsDGHBto2qJyFxbAO7uQ8Y0UVHa0J" +
			"BO/g900SAcJbcQIgRtEljIShOB8pDjrsQPxmI1BLhnjD1EhRSubwhDw5AFUCIQCN" +
			"A24pDtdOHydwtSB5+zFqFLfmVZplQM/g5kb4so70Yw==";
	public static final String PARAMATER_PRIVATE_KEY_FILENAME   = "-k";
	public static final String PARAMATER_VERBOSE                = "-v";
	public static final String PARAMATER_XML_FILENAME           = "-x";
	public static final String PARAMATER_XML_COMMON_FILENAME    = "-c";
	public static final String PARAMATER_XML_EK_FILENAME        = "-e";
	public static final String PARAMATER_XML_PLAT_SPEC_FILENAME = "-p";
	public static final String PARAMATER_OUTPUT_FILENAME        = "-o";
	public static final String PARAMATER_OUTPUT_FORMAT_DER      = "-der";

	private String xmlFilenameCommon=null;
	private String xmlFilenamePlatSpec=null;
	private String xmlFilenameEK=null;
	private String privateKeyFilename=null;
	private String outputFilename=null;
	private ArrayList<String> xmlFilenameArray = new ArrayList<String>();
	private boolean verbose=false; // default to non-verbose
	private boolean pemOut=true; // default to output in PEM format
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		PlatformCertFromXml platformCertFromXml = new PlatformCertFromXml();
		
		if(!platformCertFromXml.parseArguments(args))
		{
			output_usage();
			System.exit(1);
		}

		boolean valid = platformCertFromXml.process();
		
		System.exit(valid? 0: 1);
	}

	private boolean process()
	{
		boolean validRC = false;
		
		PrivateKey privateKey = null;
		if(privateKeyFilename != null && privateKeyFilename.length() > 0)
		{
			try {
				privateKey = TP_FileUtils.extractPrivateKey(privateKeyFilename);
				if(verbose)
				{
					System.out.println("Successfully loaded private key " + privateKeyFilename);
				}
			} 
			catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
				System.out.println("ERROR: Failed to load Private Key from file " + privateKeyFilename + "!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
				return false;
			}
		}
		else {
			// use default generic key for signing the certificate
			try {
				System.out.println("INFO: No private key entered on command line - certificate will be signed with a default generic RSA key");
				privateKey = genDefaultPrivateKey();
			} 
			catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				System.out.println("ERROR: Failed to load default generic private Key!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
				return false;
			}
		}
		PlatformCertificateHolder platformCertificateHolder = new PlatformCertificateHolder();
		
		try {
			for(String filename: xmlFilenameArray)
			{
				PlatformCertificateData platformCertData = PlatformCertificateManager.loadFromXML(new FileInputStream(filename));
				platformCertificateHolder.loadFromJaxbObj(platformCertData);
				if(verbose)
				{
					System.out.println("Successfully processed file" + filename);
				}
			}

			platformCertificateHolder.setPrivateKey(privateKey);
			
			if(verbose)
			{
				System.out.println("Writing " + (pemOut? "PEM": "DER") + " formatted output to file" + outputFilename);
			}
			
			if(pemOut)
			{
				platformCertificateHolder.writeToFilePEM(new File(outputFilename));
			}
			else {
				platformCertificateHolder.writeToFileDER(new File(outputFilename));
			}

			validRC = true;
		} 
		catch (FileNotFoundException e) {
			System.out.println(e.getLocalizedMessage());
//			e.printStackTrace();
		} 
		catch (JAXBException e) {
			System.out.println(e.getLocalizedMessage());
//			e.printStackTrace();
		} 
		catch (OperatorCreationException e) {
			System.out.println(e.getLocalizedMessage());
//			e.printStackTrace();
		} 
		catch (IOException e) {
			System.out.println(e.getLocalizedMessage());
//			e.printStackTrace();
		}

		
		return validRC;
	}

	private boolean parseArguments(String[] args)
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
					
					if(parameter[0].equals(PARAMATER_XML_FILENAME))
					{
						xmlFilenameArray.add(parameter[1]);
					}
					else if(parameter[0].equals(PARAMATER_PRIVATE_KEY_FILENAME))
					{
						privateKeyFilename = parameter[1];
					}
					else if(parameter[0].equals(PARAMATER_OUTPUT_FILENAME))
					{
						outputFilename = parameter[1];
					}
					else if(parameter[0].equals(PARAMATER_XML_COMMON_FILENAME))
					{
						xmlFilenameCommon = parameter[1];
					}
					else if(parameter[0].equals(PARAMATER_XML_PLAT_SPEC_FILENAME))
					{
						xmlFilenamePlatSpec = parameter[1];
					}
					else if(parameter[0].equals(PARAMATER_XML_EK_FILENAME))
					{
						xmlFilenameEK = parameter[1];
					}
				}
			}
			else if(arg.equals(PARAMATER_VERBOSE)){
				verbose = true;
			}
			else if(arg.equals(PARAMATER_OUTPUT_FORMAT_DER))
			{
				pemOut = false;
			}
		}
		
		if(verbose)
		{
			System.out.println("Xml Common Fields File: " + xmlFilenameCommon);
			System.out.println("Xml Platform Specific Fields File: " + xmlFilenamePlatSpec);
			System.out.println("Xml EK Fields File: " + xmlFilenameEK);
			System.out.println("Additional Xml Files: " + xmlFilenameArray.toString());
			System.out.println("Private Key Filename: " + privateKeyFilename);
			System.out.println("Output Filename: " + outputFilename);
			System.out.println("Verbose Mode: " + verbose);
			System.out.println("Output Format: " + (pemOut? "PEM": "DER"));			
		}
		
		return argsAreValid();
	}

	private boolean argsAreValid()
	{
		if(xmlFilenameCommon != null)
		{
			xmlFilenameCommon  = TP_FileUtils.validateFile(xmlFilenameCommon, verbose);
		}
		
		if(xmlFilenamePlatSpec != null)
		{
			xmlFilenamePlatSpec = TP_FileUtils.validateFile(xmlFilenamePlatSpec, verbose);
		}
		
		if(xmlFilenameEK != null)
		{
			xmlFilenameEK = TP_FileUtils.validateFile(xmlFilenameEK, verbose);
		}
		
		if(privateKeyFilename != null && privateKeyFilename.length() > 0)
		{
			privateKeyFilename = TP_FileUtils.validateFile(privateKeyFilename, verbose);
			if(privateKeyFilename == null)
			{
				System.out.println("ERROR: Failed to proces private key file: " + privateKeyFilename + "!");
				return false;
			}
		}
		
		if(outputFilename == null || outputFilename.length() <= 0)
		{
			System.out.println("ERROR: Missing output file argument (" + PARAMATER_OUTPUT_FILENAME + ")");
			return false;
		}

		ArrayList<String> tmp_xmlFilenameArray = new ArrayList<String>(xmlFilenameArray);
		for(String filename: tmp_xmlFilenameArray)
		{
			if(filename != null)
			{
				if(TP_FileUtils.validateFile(filename, verbose) == null)
				{
					System.out.println("Could not read xml file " + filename + "! Ignoring paramter.");
					xmlFilenameArray.remove(filename);
				}
			}
		}
		
		if(xmlFilenameEK != null)
		{
			xmlFilenameArray.add(0, xmlFilenameEK);
		}
		
		if(xmlFilenamePlatSpec != null)
		{
			xmlFilenameArray.add(0, xmlFilenamePlatSpec);
		}
		
		if(xmlFilenameCommon != null)
		{
			xmlFilenameArray.add(0, xmlFilenameCommon);
		}
		
		if(xmlFilenameArray.isEmpty())
		{
			System.out.println("ERROR: No valid XML PlatformCertificate fields files!");
			return false;
		}
				
		return true;
	}		
	
	private static void output_usage()
	{
		final String usage = 
				"\n\nUSAGE: \n PlatformCertFromXml " +
						"[" + PARAMATER_XML_FILENAME + "=<filename (xml) with PlatformCertificate fields>]\n\t" +
						"[" + PARAMATER_XML_COMMON_FILENAME +"=<filename (xml) with common PlatformCertificates fields>]\n\t" + 
						"[" + PARAMATER_XML_PLAT_SPEC_FILENAME +"=<filename (xml) with platform specific PlatformCertificates fields>]\n\t" + 
						"[" + PARAMATER_XML_EK_FILENAME +"=<filename (xml) with fields from the EK certificate>]\n\t" + 
						PARAMATER_PRIVATE_KEY_FILENAME +"=<private key filename (PEM or DER)>\n\t" + 
						PARAMATER_OUTPUT_FILENAME +"=<output filename>\n\t" + 
						"[" + PARAMATER_VERBOSE +"]\n\t" + 
						"[" + PARAMATER_OUTPUT_FORMAT_DER +"]\n\n" + 
						"Note: do not include space before or after the '=' in specifying command line arguments.\n" + 
						"Any number of XML PlatformCertificate field files (" + PARAMATER_XML_FILENAME + ") may be used.\n" +
						"The Common PlatformCertificate fields XML file (" + PARAMATER_XML_COMMON_FILENAME + ")\n" +
						"and the platform specific PlatformCertificate fields XML file (" + PARAMATER_XML_PLAT_SPEC_FILENAME + ") can be used with or without any other " +
						PARAMATER_XML_FILENAME + " file, but at least one XML files must be included. \n" +
						"The contents of the XML files will be appended \"on top of\" each other. Fields in files listed later on the command line will replace " +
						"fields in files listed earlier if they overlap.\n" +
						"The common fields file (" + PARAMATER_XML_COMMON_FILENAME + ") will always applied first and the platform specific fields (" +
						PARAMATER_XML_PLAT_SPEC_FILENAME + ") will be applied next.\n\n" +
						PARAMATER_OUTPUT_FORMAT_DER  + " If this parameter is present the output file will be in DER format otherwise  the output format will be in PEM format.\n" +
						PARAMATER_VERBOSE + " Verbose mode";
		
		System.out.println(usage);
	}

	public static PrivateKey genDefaultPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		 byte[] data = javax.xml.bind.DatatypeConverter.parseBase64Binary(defaultPrivateKeyString);
		 PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
		 KeyFactory fact = KeyFactory.getInstance("RSA");
		 return fact.generatePrivate(spec);	
	}
}
