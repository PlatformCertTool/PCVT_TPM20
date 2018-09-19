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
 */

/**
 * @author trustiphi
 *
 * This class holds a collection of static file verification,
 * parsing, read, and write helper functions used by other 
 * classes in the com.trustiphi.intelproj.* packages.
 */
package com.trustiphi.tpm2verification;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class TP_FileUtils {
    public static final String LOG_PREFIX_INFO   = "INFO: ";
    public static final String LOG_PREFIX_ERROR  = "ERROR: ";
    public static final String LOG_PREFIX_RESULT = "RESULT: ";
	
    public static String validateFile(String fileName, boolean verbose) {
        String result = null;

        if (!fileName.contains("\\") && !fileName.contains("/")) {
        	if (verbose) System.out.println("Folder path not included... use relative path");
            Path currentRelativePath = Paths.get("");
            String relativePath = currentRelativePath.toAbsolutePath().toString();
//            fileName = relativePath + "\\" + fileName;
            fileName = relativePath + "/" + fileName;
        }

        File file = new File(fileName);
        if (file.exists()) {
            result = fileName;
            if (verbose) System.out.println(LOG_PREFIX_INFO + " Located " + fileName);
        } else {
            System.out.println(LOG_PREFIX_ERROR + " " + fileName + " not found");
        }
        return result;
    }
    
    public static String readFile(String filename, boolean verbose) throws IOException {
    	Path path = Paths.get(filename);
    	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " Reading file: " + path);
    	}
    	byte[] encoded = Files.readAllBytes(path);
      	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " Number of bytes read: " + encoded.length);
    	}
      	return new String(encoded, Charset.defaultCharset());
    }
    
    public static byte[] readBinaryFile(String filename, boolean verbose) throws IOException {
    	Path path = Paths.get(filename);
    	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " Reading binary file: " + path);
    	}
    	byte[] filebytes = Files.readAllBytes(path);
      	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " Number of bytes read: " + filebytes.length);
    	}
      	return filebytes;
    }
    
    public static Object readPemFile(String filename, boolean verbose) throws IOException {
    	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " Reading PEM file: " + filename);
    	}
    	FileReader fileReader = new FileReader(filename);
    	PEMParser pemReader = new PEMParser(fileReader);
    	Object retObj = pemReader.readObject();
    	pemReader.close();
    	
      	return retObj;
    }
    
    public static void writePemFile(String pemContentType, byte[] contents, String filename, boolean verbose) throws IOException {
    	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " writing " + pemContentType + " file: " + filename);
    	}
    	
    	writePemFile(pemContentType, contents, new File(filename), verbose);
    }

    public static void writePemFile(String pemContentType, byte[] contents, File file, boolean verbose) throws IOException {
    	FileWriter fileWriter = new FileWriter(file);
    	PemWriter pemWriter = new PemWriter(fileWriter);
    	
    	PemObjectGenerator pemObjGenerator = new PemObject(pemContentType, contents);

    	pemWriter.writeObject(pemObjGenerator);
    	pemWriter.close();
    }

    public static void writeBinFile(byte[] contents, String filename, boolean verbose) throws IOException {
    	Path path = Paths.get(filename);
    	if(verbose) {
            System.out.println(LOG_PREFIX_INFO + " writing attribute certificate file: " + path);
    	}
    	Files.write(path, contents);
    }
    
    

    public static PrivateKey extractPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        PemReader reader = null;

        try {
	        reader = new PemReader(new FileReader(fileName));
	        PemObject pemObject = reader.readPemObject();
	        if(pemObject != null) {
	        	PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
	        	privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
	        }
		} finally {
        	if(reader != null) {
        		reader.close();
        	}
        }
        return privateKey;
    }

    public static PublicKey extractPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = null;
        PemReader reader = null;

        try {
	        reader = new PemReader(new FileReader(fileName));
	        PemObject pemObject = reader.readPemObject();
	        if(pemObject != null) {
	        	X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObject.getContent());
	        	publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
	        }
		} finally {
        	if(reader != null) {
        		reader.close();
        	}
        }
        return publicKey;
    }
}
