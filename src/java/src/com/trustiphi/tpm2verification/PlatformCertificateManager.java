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

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;


import com.trustiphi.tpm2verification.platformcertparse.*;

/**
 * @author Marshall Shapiro/TrustiPhi, LLC
 *
 */
public class PlatformCertificateManager 
{
	private PlatformCertificateHolder platformCertificateHolder;

	public static PlatformCertificateData loadFromXML(InputStream platformCertXml) throws JAXBException
	{
		JAXBContext jc = JAXBContext.newInstance("com.trustiphi.tpm2verification.platformcertparse",  com.trustiphi.tpm2verification.platformcertparse.ObjectFactory.class.getClassLoader());	

		Unmarshaller u = jc.createUnmarshaller();
		PlatformCertificateData platformCertData = (PlatformCertificateData) u.unmarshal(platformCertXml);
				
	    return platformCertData;
	}


	public static void writeToXML(PlatformCertificateHolder platformCertificateHolder, OutputStream platformCertXmlOut) 
			throws JAXBException
	{
		JAXBContext jc = JAXBContext.newInstance("com.trustiphi.tpm2verification.platformcertparse",  com.trustiphi.tpm2verification.platformcertparse.ObjectFactory.class.getClassLoader());	

		Marshaller marshaller = jc.createMarshaller();
		PlatformCertificateData platformCertData = platformCertificateHolder.toJaxbObj();
		
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
		marshaller.marshal(platformCertData, platformCertXmlOut);
	}


	public static String platformCertificateDataToString(PlatformCertificateData platformCertData)
	{
		String out = new String();
		
		out += "AuthorityAccessMethod: " + platformCertData.getAuthorityAccessMethod() + "\n";
//		out += "AuthorityAccessLocation: " + platformCertData.getAuthorityAccessLocation() + "\n";
		out += "AuthorityAccessLocation: {\n";
		XmlGeneralName generalName = platformCertData.getAuthorityAccessLocation();
		if(generalName != null)
		{
			out += "\ttag: " + generalName.getTag().value() + "\n";
			out += "\tname: " + generalName.getName() + "\n";
		}
		out += "}\n";
		out += "AuthorityKeyIdentifier: " + platformCertData.getAuthorityKeyIdentifier() + "\n";
		out += "EKCertSerialNumber: " + platformCertData.getEKCertSerialNumber() + "\n";
		out += "EKIssuer: " + platformCertData.getEKIssuer() + "\n";
		out += "Issuer: " + platformCertData.getIssuer() + "\n";
		out += "PlatformManufacturerStr: " + platformCertData.getPlatformManufacturerStr() + "\n";
		out += "PlatformManufacturerId: " + platformCertData.getPlatformManufacturerId() + "\n";
		out += "PlatformModel: " + platformCertData.getPlatformModel() + "\n";
		out += "PlatformCertSerialNumber: " + platformCertData.getPlatformCertSerialNumber() + "\n";
		out += "PlatformVersion: " + platformCertData.getPlatformVersion() + "\n";
		out += "SignatureAlgorithm: " + platformCertData.getSignatureAlgorithm() + "\n";
		out += "SignatureValue: " + platformCertData.getSignatureValue() + "\n";
		out += "MajorVersion: " + platformCertData.getMajorVersion() + "\n";
		out += "MinorVersion: " + platformCertData.getMinorVersion() + "\n";
		out += "PlatformClass: " + platformCertData.getPlatformClass() + "\n";
		out += "CertifcatePolicies: [\n";
		for(XmlCertificatePolicies cp: platformCertData.getCertificatePolicies())
		{
			out += "\t{\n";
			out += "\t\tPolicyIdentifier: " + cp.getPolicyIdentifier() + "\n";
			out += "\t\tPolicyQualifiers: [\n";
			for(XmlPolicyQualifier pq: cp.getPolicyQualifier())
			{
				out += "\t\t\t{\n";
				out += "\t\t\t\tPolicyQualifierId: " + pq.getPolicyQualifierId() + "\n";
				out += "\t\t\t\tQualifier: " + pq.getQualifier() + "\n";
				out += "\t\t\t}\n";
			}
			out += "\t\t]\n";
			out += "\t}\n";
		}
		out += "]\n";
		out += "Revision: " + platformCertData.getRevision() + "\n";
		out += "ValidFrom: " + platformCertData.getValidFrom() + "\n";
		out += "ValidTo: " + platformCertData.getValidTo() + "\n";
		out += "Ver: " + platformCertData.getVer() + "\n";
		out += "PlatformAssertionsVersion: " + platformCertData.getPlatformAssertionsVersion() + "\n";
		out += "PlatformAssertionsCCInfo: {" + "\n";
		XmlCommonCriteriaMeasures ccInfo = platformCertData.getPlatformAssertionsCCInfo();
		if(ccInfo != null)
		{
			out += "\tAssurancelevel: " + ccInfo.getAssurancelevel() + "\n";
			out += "\tEvaluationStatus: " + ccInfo.getEvaluationStatus() + "\n";
			out += "\tStrengthOfFunction: " + ccInfo.getStrengthOfFunction() + "\n";
			out += "\tProfileOid: " + ccInfo.getProfileOid() + "\n";
			out += "\tProfileUri: {" + "\n";
			XmlURIReference uriReference = ccInfo.getProfileUri();
			out += "\t\tuniformResourceIdentifier: " + uriReference.getUniformResourceIdentifier() + "\n";
			out += "\t\tHashAlgorithm: " + uriReference.getHashAlgorithm() + "\n";
			out += "\t\tHashValue: " + uriReference.getHashValue() + "\n";
			out += "\t} "  + "\n";
			out += "\tTargetOid: " + ccInfo.getTargetOid() + "\n";
			out += "\tTargetUri: {" + "\n";
			uriReference = ccInfo.getTargetUri();
			out += "\t\tuniformResourceIdentifier: " + uriReference.getUniformResourceIdentifier() + "\n";
			out += "\t\tHashAlgorithm: " + uriReference.getHashAlgorithm() + "\n";
			out += "\t\tHashValue: " + uriReference.getHashValue() + "\n";
			out += "\t} "  + "\n";
		}
		out += "} "  + "\n";
		out += "PlatformAssertionsFipsLevelVersion: " + platformCertData.getPlatformAssertionsFipsLevelVersion() + "\n";
		out += "PlatformAssertionsFipsLevel: " + platformCertData.getPlatformAssertionsFipsLevel() + "\n";
		out += "PlatformAssertionsFipsLevelPlus: " + platformCertData.isPlatformAssertionsFipsLevelPlus() + "\n";
		out += "PlatformAssertionsRtmType: " + platformCertData.getPlatformAssertionsRtmType() + "\n";
		out += "PlatformAssertionsIso9000Certified: " + platformCertData.isPlatformAssertionsIso9000Certified() + "\n";
		out += "PlatformAssertionsIso9000Uri: " + platformCertData.getPlatformAssertionsIso9000Uri() + "\n";
        out += "CRLDistributionPoints: [\n";
		for(XmlCRLDistributionPoints cdp: platformCertData.getCRLDistributionPoints())
        {
            out += "\t{\n";
            out += "\t\tDistributionPoint: {\n";
            if (cdp.getDistributionPoint() != null)
            {
                List<XmlGeneralName> distributionPointInfo;         
                if(cdp.getDistributionPoint().getFullname().size() > 0)
                {
                    out += "\t\t\tFullName: [\n";
                    distributionPointInfo = cdp.getDistributionPoint().getFullname();
                }
                else
                {
                    out += "\t\t\tNameRelativeToCRLIssuer: [\n";
                    distributionPointInfo = cdp.getDistributionPoint().getNameRelativeToCRLIssuer();
                }
                for (XmlGeneralName xmlGeneralName : distributionPointInfo)
                {
                    out += "\t\t\t\t{\n";
                    if (xmlGeneralName.getTag() != null)
                    {
                        out += "\t\t\t\t\tTag: " + xmlGeneralName.getTag().value() + "\n";
                    }
                    out += "\t\t\t\t\tName: " + xmlGeneralName.getName() + "\n";
                    out += "\t\t\t\t}\n";
                }
                out += "\t\t\t]\n"; 
            }
            out += "\t\t}\n";
            out += "\t\tReasonFlags: " + cdp.getReasons() + "\n";
            out += "\t\tCRLIssuer: {\n";
            if (cdp.getCRLIssuer() != null)
            {
                if (cdp.getCRLIssuer().getTag() != null)
                {
                    out += "\t\t\tTag: " + cdp.getCRLIssuer().getTag().value() + "\n";
                }                
                out += "\t\t\tName: " + cdp.getCRLIssuer().getName() + "\n";
            }
            out += "\t\t}\n";
            out += "\t}\n";
        }
        out += "]\n";
        out += "TcgCredentialSpecificationMajorVersion: " + platformCertData.getTcgCredentialSpecificationMajorVersion() + "\n";
        out += "TcgCredentialSpecificationMinorVersion: " + platformCertData.getTcgCredentialSpecificationMinorVersion() + "\n";
        out += "TcgCredentialSpecificationMinorRevision: " + platformCertData.getTcgCredentialSpecificationRevision() + "\n";
        XmlURIReference uriReference = platformCertData.getPlatformConfigUri();
        out += "PlatformConfigUri: {\n";
        out += "\tUniformResourceIdentifier: " + uriReference.getUniformResourceIdentifier() + "\n";
        out += "\tHashAlgorithm: " + uriReference.getHashAlgorithm() + "\n";
        out += "\tHashValue: " + uriReference.getHashValue() + "\n";
        out += "}\n";        
        out += "ComponentIdentifier: [\n";
        if (platformCertData.getComponentIdentifier() != null)
        {
            for (XmlComponentIdentifier xmlComponentIdentifier : platformCertData.getComponentIdentifier())
            {
                if (xmlComponentIdentifier != null)
                {
                    out += "\t{\n";
                    out += "\t\tComponentManufacturer: " + xmlComponentIdentifier.getComponentManufacturer() + "\n";
                    out += "\t\tComponentModel: " + xmlComponentIdentifier.getComponentModel() + "\n";
                    out += "\t\tComponentSerial: " + xmlComponentIdentifier.getComponentSerial() + "\n";
                    out += "\t\tComponentRevision: " + xmlComponentIdentifier.getComponentRevision() + "\n";
                    out += "\t\tComponentManufacturerId: " + xmlComponentIdentifier.getComponentManufacturerId() + "\n";
                    out += "\t\tFieldReplaceable: " + xmlComponentIdentifier.isFieldReplaceable().toString() + "\n";
                    out += "\t\tComponentAddress: [\n";
                    if (xmlComponentIdentifier.getComponentAddress() != null)
                    {
                        for (XmlComponentAddress xmlComponentAddress : xmlComponentIdentifier.getComponentAddress())
                        {
                            if (xmlComponentAddress != null)
                            {
                                out += "\t\t\t{\n";
                                out += "\t\t\t\tAddressType: " + xmlComponentAddress.getAddressType() + "\n";
                                out += "\t\t\t\tAddressValue: " + xmlComponentAddress.getAddressValue() + "\n";
                                out += "\t\t\t}\n";
                            }
                        }
                    }
                    out += "\t\t]\n";
                    out += "\t}\n";
                }
            }
        }
        out += "]\n";
        out += "PlatformProperties: [\n";
        if (platformCertData.getPlatformProperties() != null)
        {
            for (XmlProperties xmlProperties : platformCertData.getPlatformProperties())
            {
                if (xmlProperties != null)
                {
                    out += "\t{\n";
                    out += "\t\tPropertyName: " + xmlProperties.getPropertyName() + "\n";
                    out += "\t\tPropertyValue: " + xmlProperties.getPropertyValue() + "\n";
                    out += "\t}\n";
                }
            }
        }
        out += "]\n";
        XmlURIReference platformPropertiesUriInfo = platformCertData.getPlatformPropertiesUri();
        out +="PlatformPropertiesUri: {\n";
        out += "\tUniformResourceIdentifier: " + platformPropertiesUriInfo.getUniformResourceIdentifier() + "\n";
        out += "\tHashAlgorithm: " + platformPropertiesUriInfo.getHashAlgorithm() + "\n";
        out += "\tHashValue: " + platformPropertiesUriInfo.getHashValue() + "\n";
        out += "}\n";
        
		return out;
	}

	private void LOG_ERRROR(String methodName, String errString)
	{
		System.out.println("[PlatformCertificateManager." + methodName + "] ERROR: " + errString);
	}
}
