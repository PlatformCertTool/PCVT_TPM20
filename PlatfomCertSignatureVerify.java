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
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 */
public class PlatfomCertSignatureVerify {
	public static final String PARAMATER_PLATFORM_CERT_FILENAME = "-f";
	public static final String PARAMATER_PUBLIC_KEY_FILENAME    = "-k";
	public static final String PARAMATER_VERBOSE                = "-v";
	public static final String PARAMATER_INPUT_FORMAT_DER       = "-der";

	private static String  platformCertFilename=null;
	private static String  publicKeyFilename=null;
	private static boolean verbose=false; // default to non-verbose
	private static boolean pemIn=true;    // default to input in PEM format

	private static boolean signatureVerified = false;
	
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
		
		System.exit((valid && signatureVerified)? 0: 1);
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
				System.out.println("WARNING: Failed parsing Platform Certificate file as PEM formatted file! (Will attempt to parse as DER.)\n" + e.getLocalizedMessage());
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

		PublicKey publicKey = null;
		try {
			publicKey = TP_FileUtils.extractPublicKey(publicKeyFilename);
			if(verbose)
			{
				System.out.println("Successfully loaded public key " + publicKeyFilename);
			}
		} 
		catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			System.out.println("ERROR: Failed to load Public Key from file " + publicKeyFilename + "!");
			System.out.println("ERROR: " + e.getLocalizedMessage());
			return false;
		}
		
		
		if(platfomCertLoaded && publicKey != null)
		{
			try {
				signatureVerified = platformCertificateHolder.verifySignature(publicKey);
				if(signatureVerified)
				{
					System.out.println("Signature verified.");
				}
				else {
					System.out.println("Signature verification failed. Platform certificate signature does not match input public key!");
				}
			} 
			catch (InvalidKeyException e) {
				System.out.println("ERROR: Unable to verify platform certificate signature; Bad Public Key input!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
			} 
			catch (OperatorCreationException e) {
				System.out.println("ERROR: Unable to verify platform certificate signature; Problem parsing updates to certificate!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
			}
			catch (NoSuchAlgorithmException e) {
				System.out.println("ERROR: Unable to verify platform certificate signature; Invalid signature algorithm found in certificate!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
			}
			catch (SignatureException e) {
				System.out.println("ERROR: Unable to verify platform certificate signature; Bad signature ot signature algorithm!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
			}
			catch (IOException e) {
				System.out.println("ERROR: Unable to verify platform certificate signature; Parsing error!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
			}
			catch (CertificateException e) {
				System.out.println("ERROR: Unable to verify platform certificate signature; Badly formed certificate!");
				System.out.println("ERROR: " + e.getLocalizedMessage());
			}
			
			wasProcessedSuccessfully = true;
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
					else if(parameter[0].equals(PARAMATER_PUBLIC_KEY_FILENAME))
					{
						publicKeyFilename = parameter[1];
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
			System.out.println("Public Key Filename: " + publicKeyFilename);
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

		if(publicKeyFilename != null)
		{
			publicKeyFilename  = TP_FileUtils.validateFile(publicKeyFilename, verbose);
		}
		else {
			System.out.println("ERROR: Missing Pubic Key file command line argument (" + PARAMATER_PUBLIC_KEY_FILENAME + ")!");
			return false;
		}
		
		if(publicKeyFilename == null)
		{
			System.out.println("ERROR: Can't find Public Key file!");
			return false;
		}

		
		return true;
	}		
	
	private static void output_usage()
	{
		final String usage = 
				"\nUSAGE: \n PlatformCertToXml " +
						PARAMATER_PLATFORM_CERT_FILENAME + "=<PlatformCertificate file> " +
						PARAMATER_PUBLIC_KEY_FILENAME +"=<public key file> " + 
						"[" + PARAMATER_VERBOSE +"] " + 
						"[" + PARAMATER_INPUT_FORMAT_DER +"]\n\n" + 
						"Note: do not include space before or after the '=' in specifying command line arguments.\n" + 
						PARAMATER_PLATFORM_CERT_FILENAME + "   Platform Certificate file - could be in PEM or DER format. If '" + PARAMATER_INPUT_FORMAT_DER + "' is not used an attempt is first made to parse as PEM and if that fails it is parsed as DER.\n" +
						PARAMATER_PUBLIC_KEY_FILENAME +"   Public Key to using in verifying the Platform Certificate." +
						PARAMATER_INPUT_FORMAT_DER  + " Skip attempt to parse certificate as a PEM file - only parse as a DER.\n" +
						PARAMATER_VERBOSE + "   Verbose mode";
		
		System.out.println(usage);
	}
}
