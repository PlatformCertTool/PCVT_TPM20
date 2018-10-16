//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.09.06 at 02:40:54 PM EDT 
//


package com.trustiphi.tpm2verification.platformcertparse;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="EKCertSerialNumber" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformManufacturerStr" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformModel" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformVersion" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformSerialNumber" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformManufacturerId" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="EKIssuer" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="ValidTo" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="PlatformClass" minOccurs="0">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *               &lt;length value="4"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="MajorVersion" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="MinorVersion" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="Revision" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="SignatureValue" type="{http://www.w3.org/2001/XMLSchema}hexBinary" minOccurs="0"/>
 *         &lt;element name="AMT" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="ValidFrom" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="Issuer" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="CertificatePolicies" type="{www.trustiphi.com/platfromcertificateparser}XmlCertificatePolicies" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="AuthorityKeyIdentifier" type="{http://www.w3.org/2001/XMLSchema}hexBinary" minOccurs="0"/>
 *         &lt;element name="AuthorityAccessMethod" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="AuthorityAccessLocation" type="{www.trustiphi.com/platfromcertificateparser}XmlGeneralName" minOccurs="0"/>
 *         &lt;element name="CRLDistributionPoints" type="{www.trustiphi.com/platfromcertificateparser}XmlCRLDistributionPoints" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="SignatureAlgorithm" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsVersion" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsCCInfo" type="{www.trustiphi.com/platfromcertificateparser}XmlCommonCriteriaMeasures" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsFipsLevelVersion" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsFipsLevel" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsFipsLevelPlus" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsRtmType" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsIso9000Certified" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="PlatformAssertionsIso9000Uri" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="TcgAtPlatformSerial" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="TcgCredentialSpecificationMajorVersion" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="TcgCredentialSpecificationMinorVersion" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="TcgCredentialSpecificationRevision" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="PlatformConfigUri" type="{www.trustiphi.com/platfromcertificateparser}XmlURIReference" minOccurs="0"/>
 *         &lt;element name="ComponentIdentifier" type="{www.trustiphi.com/platfromcertificateparser}XmlComponentIdentifier" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="PlatformProperties" type="{www.trustiphi.com/platfromcertificateparser}XmlProperties" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="PlatformPropertiesUri" type="{www.trustiphi.com/platfromcertificateparser}XmlURIReference" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ver" use="required" type="{http://www.w3.org/2001/XMLSchema}int" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "ekCertSerialNumber",
    "platformManufacturerStr",
    "platformModel",
    "platformVersion",
    "platformSerialNumber",
    "platformManufacturerId",
    "ekIssuer",
    "validTo",
    "platformClass",
    "majorVersion",
    "minorVersion",
    "revision",
    "signatureValue",
    "amt",
    "validFrom",
    "issuer",
    "certificatePolicies",
    "authorityKeyIdentifier",
    "authorityAccessMethod",
    "authorityAccessLocation",
    "crlDistributionPoints",
    "signatureAlgorithm",
    "platformAssertionsVersion",
    "platformAssertionsCCInfo",
    "platformAssertionsFipsLevelVersion",
    "platformAssertionsFipsLevel",
    "platformAssertionsFipsLevelPlus",
    "platformAssertionsRtmType",
    "platformAssertionsIso9000Certified",
    "platformAssertionsIso9000Uri",
    "tcgAtPlatformSerial",
    "tcgCredentialSpecificationMajorVersion",
    "tcgCredentialSpecificationMinorVersion",
    "tcgCredentialSpecificationRevision",
    "platformConfigUri",
    "componentIdentifier",
    "platformProperties",
    "platformPropertiesUri"
})
@XmlRootElement(name = "PlatformCertificateData")
public class PlatformCertificateData {

    @XmlElement(name = "EKCertSerialNumber")
    protected String ekCertSerialNumber;
    @XmlElement(name = "PlatformManufacturerStr")
    protected String platformManufacturerStr;
    @XmlElement(name = "PlatformModel")
    protected String platformModel;
    @XmlElement(name = "PlatformVersion")
    protected String platformVersion;
    @XmlElement(name = "PlatformSerialNumber")
    protected String platformSerialNumber;
    @XmlElement(name = "PlatformManufacturerId")
    protected List<String> platformManufacturerId;
    @XmlElement(name = "EKIssuer")
    protected String ekIssuer;
    @XmlElement(name = "ValidTo")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validTo;
    @XmlElement(name = "PlatformClass")
    protected String platformClass;
    @XmlElement(name = "MajorVersion")
    protected Integer majorVersion;
    @XmlElement(name = "MinorVersion")
    protected Integer minorVersion;
    @XmlElement(name = "Revision")
    protected Integer revision;
    @XmlElement(name = "SignatureValue", type = String.class)
    @XmlJavaTypeAdapter(HexBinaryAdapter.class)
    @XmlSchemaType(name = "hexBinary")
    protected byte[] signatureValue;
    @XmlElement(name = "AMT")
    protected Boolean amt;
    @XmlElement(name = "ValidFrom")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validFrom;
    @XmlElement(name = "Issuer")
    protected String issuer;
    @XmlElement(name = "CertificatePolicies")
    protected List<XmlCertificatePolicies> certificatePolicies;
    @XmlElement(name = "AuthorityKeyIdentifier", type = String.class)
    @XmlJavaTypeAdapter(HexBinaryAdapter.class)
    @XmlSchemaType(name = "hexBinary")
    protected byte[] authorityKeyIdentifier;
    @XmlElement(name = "AuthorityAccessMethod")
    protected String authorityAccessMethod;
    @XmlElement(name = "AuthorityAccessLocation")
    protected XmlGeneralName authorityAccessLocation;
    @XmlElement(name = "CRLDistributionPoints")
    protected List<XmlCRLDistributionPoints> crlDistributionPoints;
    @XmlElement(name = "SignatureAlgorithm")
    protected String signatureAlgorithm;
    @XmlElement(name = "PlatformAssertionsVersion")
    protected Integer platformAssertionsVersion;
    @XmlElement(name = "PlatformAssertionsCCInfo")
    protected XmlCommonCriteriaMeasures platformAssertionsCCInfo;
    @XmlElement(name = "PlatformAssertionsFipsLevelVersion")
    protected String platformAssertionsFipsLevelVersion;
    @XmlElement(name = "PlatformAssertionsFipsLevel")
    protected Integer platformAssertionsFipsLevel;
    @XmlElement(name = "PlatformAssertionsFipsLevelPlus")
    protected Boolean platformAssertionsFipsLevelPlus;
    @XmlElement(name = "PlatformAssertionsRtmType")
    protected Integer platformAssertionsRtmType;
    @XmlElement(name = "PlatformAssertionsIso9000Certified")
    protected Boolean platformAssertionsIso9000Certified;
    @XmlElement(name = "PlatformAssertionsIso9000Uri")
    protected String platformAssertionsIso9000Uri;
    @XmlElement(name = "TcgAtPlatformSerial")
    protected String tcgAtPlatformSerial;
    @XmlElement(name = "TcgCredentialSpecificationMajorVersion")
    protected Integer tcgCredentialSpecificationMajorVersion;
    @XmlElement(name = "TcgCredentialSpecificationMinorVersion")
    protected Integer tcgCredentialSpecificationMinorVersion;
    @XmlElement(name = "TcgCredentialSpecificationRevision")
    protected Integer tcgCredentialSpecificationRevision;
    @XmlElement(name = "PlatformConfigUri")
    protected XmlURIReference platformConfigUri;
    @XmlElement(name = "ComponentIdentifier")
    protected List<XmlComponentIdentifier> componentIdentifier;
    @XmlElement(name = "PlatformProperties")
    protected List<XmlProperties> platformProperties;
    @XmlElement(name = "PlatformPropertiesUri")
    protected XmlURIReference platformPropertiesUri;
    @XmlAttribute(name = "ver", required = true)
    protected int ver;

    /**
     * Gets the value of the ekCertSerialNumber property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEKCertSerialNumber() {
        return ekCertSerialNumber;
    }

    /**
     * Sets the value of the ekCertSerialNumber property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEKCertSerialNumber(String value) {
        this.ekCertSerialNumber = value;
    }

    /**
     * Gets the value of the platformManufacturerStr property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformManufacturerStr() {
        return platformManufacturerStr;
    }

    /**
     * Sets the value of the platformManufacturerStr property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformManufacturerStr(String value) {
        this.platformManufacturerStr = value;
    }

    /**
     * Gets the value of the platformModel property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformModel() {
        return platformModel;
    }

    /**
     * Sets the value of the platformModel property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformModel(String value) {
        this.platformModel = value;
    }

    /**
     * Gets the value of the platformVersion property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformVersion() {
        return platformVersion;
    }

    /**
     * Sets the value of the platformVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformVersion(String value) {
        this.platformVersion = value;
    }

    /**
     * Gets the value of the platformSerialNumber property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformSerialNumber() {
        return platformSerialNumber;
    }

    /**
     * Sets the value of the platformSerialNumber property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformSerialNumber(String value) {
        this.platformSerialNumber = value;
    }

    /**
     * Gets the value of the platformManufacturerId property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the platformManufacturerId property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPlatformManufacturerId().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getPlatformManufacturerId() {
        if (platformManufacturerId == null) {
            platformManufacturerId = new ArrayList<String>();
        }
        return this.platformManufacturerId;
    }

    /**
     * Gets the value of the ekIssuer property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEKIssuer() {
        return ekIssuer;
    }

    /**
     * Sets the value of the ekIssuer property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEKIssuer(String value) {
        this.ekIssuer = value;
    }

    /**
     * Gets the value of the validTo property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getValidTo() {
        return validTo;
    }

    /**
     * Sets the value of the validTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setValidTo(XMLGregorianCalendar value) {
        this.validTo = value;
    }

    /**
     * Gets the value of the platformClass property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformClass() {
        return platformClass;
    }

    /**
     * Sets the value of the platformClass property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformClass(String value) {
        this.platformClass = value;
    }

    /**
     * Gets the value of the majorVersion property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getMajorVersion() {
        return majorVersion;
    }

    /**
     * Sets the value of the majorVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setMajorVersion(Integer value) {
        this.majorVersion = value;
    }

    /**
     * Gets the value of the minorVersion property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getMinorVersion() {
        return minorVersion;
    }

    /**
     * Sets the value of the minorVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setMinorVersion(Integer value) {
        this.minorVersion = value;
    }

    /**
     * Gets the value of the revision property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getRevision() {
        return revision;
    }

    /**
     * Sets the value of the revision property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setRevision(Integer value) {
        this.revision = value;
    }

    /**
     * Gets the value of the signatureValue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }

    /**
     * Sets the value of the signatureValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureValue(byte[] value) {
        this.signatureValue = value;
    }

    /**
     * Gets the value of the amt property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isAMT() {
        return amt;
    }

    /**
     * Sets the value of the amt property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setAMT(Boolean value) {
        this.amt = value;
    }

    /**
     * Gets the value of the validFrom property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getValidFrom() {
        return validFrom;
    }

    /**
     * Sets the value of the validFrom property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setValidFrom(XMLGregorianCalendar value) {
        this.validFrom = value;
    }

    /**
     * Gets the value of the issuer property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the value of the issuer property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIssuer(String value) {
        this.issuer = value;
    }

    /**
     * Gets the value of the certificatePolicies property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the certificatePolicies property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCertificatePolicies().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlCertificatePolicies }
     * 
     * 
     */
    public List<XmlCertificatePolicies> getCertificatePolicies() {
        if (certificatePolicies == null) {
            certificatePolicies = new ArrayList<XmlCertificatePolicies>();
        }
        return this.certificatePolicies;
    }

    /**
     * Gets the value of the authorityKeyIdentifier property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public byte[] getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    /**
     * Sets the value of the authorityKeyIdentifier property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAuthorityKeyIdentifier(byte[] value) {
        this.authorityKeyIdentifier = value;
    }

    /**
     * Gets the value of the authorityAccessMethod property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAuthorityAccessMethod() {
        return authorityAccessMethod;
    }

    /**
     * Sets the value of the authorityAccessMethod property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAuthorityAccessMethod(String value) {
        this.authorityAccessMethod = value;
    }

    /**
     * Gets the value of the authorityAccessLocation property.
     * 
     * @return
     *     possible object is
     *     {@link XmlGeneralName }
     *     
     */
    public XmlGeneralName getAuthorityAccessLocation() {
        return authorityAccessLocation;
    }

    /**
     * Sets the value of the authorityAccessLocation property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlGeneralName }
     *     
     */
    public void setAuthorityAccessLocation(XmlGeneralName value) {
        this.authorityAccessLocation = value;
    }

    /**
     * Gets the value of the crlDistributionPoints property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the crlDistributionPoints property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCRLDistributionPoints().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlCRLDistributionPoints }
     * 
     * 
     */
    public List<XmlCRLDistributionPoints> getCRLDistributionPoints() {
        if (crlDistributionPoints == null) {
            crlDistributionPoints = new ArrayList<XmlCRLDistributionPoints>();
        }
        return this.crlDistributionPoints;
    }

    /**
     * Gets the value of the signatureAlgorithm property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Sets the value of the signatureAlgorithm property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureAlgorithm(String value) {
        this.signatureAlgorithm = value;
    }

    /**
     * Gets the value of the platformAssertionsVersion property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getPlatformAssertionsVersion() {
        return platformAssertionsVersion;
    }

    /**
     * Sets the value of the platformAssertionsVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setPlatformAssertionsVersion(Integer value) {
        this.platformAssertionsVersion = value;
    }

    /**
     * Gets the value of the platformAssertionsCCInfo property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCommonCriteriaMeasures }
     *     
     */
    public XmlCommonCriteriaMeasures getPlatformAssertionsCCInfo() {
        return platformAssertionsCCInfo;
    }

    /**
     * Sets the value of the platformAssertionsCCInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCommonCriteriaMeasures }
     *     
     */
    public void setPlatformAssertionsCCInfo(XmlCommonCriteriaMeasures value) {
        this.platformAssertionsCCInfo = value;
    }

    /**
     * Gets the value of the platformAssertionsFipsLevelVersion property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformAssertionsFipsLevelVersion() {
        return platformAssertionsFipsLevelVersion;
    }

    /**
     * Sets the value of the platformAssertionsFipsLevelVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformAssertionsFipsLevelVersion(String value) {
        this.platformAssertionsFipsLevelVersion = value;
    }

    /**
     * Gets the value of the platformAssertionsFipsLevel property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getPlatformAssertionsFipsLevel() {
        return platformAssertionsFipsLevel;
    }

    /**
     * Sets the value of the platformAssertionsFipsLevel property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setPlatformAssertionsFipsLevel(Integer value) {
        this.platformAssertionsFipsLevel = value;
    }

    /**
     * Gets the value of the platformAssertionsFipsLevelPlus property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isPlatformAssertionsFipsLevelPlus() {
        return platformAssertionsFipsLevelPlus;
    }

    /**
     * Sets the value of the platformAssertionsFipsLevelPlus property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setPlatformAssertionsFipsLevelPlus(Boolean value) {
        this.platformAssertionsFipsLevelPlus = value;
    }

    /**
     * Gets the value of the platformAssertionsRtmType property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getPlatformAssertionsRtmType() {
        return platformAssertionsRtmType;
    }

    /**
     * Sets the value of the platformAssertionsRtmType property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setPlatformAssertionsRtmType(Integer value) {
        this.platformAssertionsRtmType = value;
    }

    /**
     * Gets the value of the platformAssertionsIso9000Certified property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isPlatformAssertionsIso9000Certified() {
        return platformAssertionsIso9000Certified;
    }

    /**
     * Sets the value of the platformAssertionsIso9000Certified property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setPlatformAssertionsIso9000Certified(Boolean value) {
        this.platformAssertionsIso9000Certified = value;
    }

    /**
     * Gets the value of the platformAssertionsIso9000Uri property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPlatformAssertionsIso9000Uri() {
        return platformAssertionsIso9000Uri;
    }

    /**
     * Sets the value of the platformAssertionsIso9000Uri property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPlatformAssertionsIso9000Uri(String value) {
        this.platformAssertionsIso9000Uri = value;
    }

    /**
     * Gets the value of the tcgAtPlatformSerial property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTcgAtPlatformSerial() {
        return tcgAtPlatformSerial;
    }

    /**
     * Sets the value of the tcgAtPlatformSerial property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTcgAtPlatformSerial(String value) {
        this.tcgAtPlatformSerial = value;
    }

    /**
     * Gets the value of the tcgCredentialSpecificationMajorVersion property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getTcgCredentialSpecificationMajorVersion() {
        return tcgCredentialSpecificationMajorVersion;
    }

    /**
     * Sets the value of the tcgCredentialSpecificationMajorVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setTcgCredentialSpecificationMajorVersion(Integer value) {
        this.tcgCredentialSpecificationMajorVersion = value;
    }

    /**
     * Gets the value of the tcgCredentialSpecificationMinorVersion property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getTcgCredentialSpecificationMinorVersion() {
        return tcgCredentialSpecificationMinorVersion;
    }

    /**
     * Sets the value of the tcgCredentialSpecificationMinorVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setTcgCredentialSpecificationMinorVersion(Integer value) {
        this.tcgCredentialSpecificationMinorVersion = value;
    }

    /**
     * Gets the value of the tcgCredentialSpecificationRevision property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getTcgCredentialSpecificationRevision() {
        return tcgCredentialSpecificationRevision;
    }

    /**
     * Sets the value of the tcgCredentialSpecificationRevision property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setTcgCredentialSpecificationRevision(Integer value) {
        this.tcgCredentialSpecificationRevision = value;
    }

    /**
     * Gets the value of the platformConfigUri property.
     * 
     * @return
     *     possible object is
     *     {@link XmlURIReference }
     *     
     */
    public XmlURIReference getPlatformConfigUri() {
        return platformConfigUri;
    }

    /**
     * Sets the value of the platformConfigUri property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlURIReference }
     *     
     */
    public void setPlatformConfigUri(XmlURIReference value) {
        this.platformConfigUri = value;
    }

    /**
     * Gets the value of the componentIdentifier property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the componentIdentifier property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getComponentIdentifier().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlComponentIdentifier }
     * 
     * 
     */
    public List<XmlComponentIdentifier> getComponentIdentifier() {
        if (componentIdentifier == null) {
            componentIdentifier = new ArrayList<XmlComponentIdentifier>();
        }
        return this.componentIdentifier;
    }

    /**
     * Gets the value of the platformProperties property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the platformProperties property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPlatformProperties().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlProperties }
     * 
     * 
     */
    public List<XmlProperties> getPlatformProperties() {
        if (platformProperties == null) {
            platformProperties = new ArrayList<XmlProperties>();
        }
        return this.platformProperties;
    }

    /**
     * Gets the value of the platformPropertiesUri property.
     * 
     * @return
     *     possible object is
     *     {@link XmlURIReference }
     *     
     */
    public XmlURIReference getPlatformPropertiesUri() {
        return platformPropertiesUri;
    }

    /**
     * Sets the value of the platformPropertiesUri property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlURIReference }
     *     
     */
    public void setPlatformPropertiesUri(XmlURIReference value) {
        this.platformPropertiesUri = value;
    }

    /**
     * Gets the value of the ver property.
     * 
     */
    public int getVer() {
        return ver;
    }

    /**
     * Sets the value of the ver property.
     * 
     */
    public void setVer(int value) {
        this.ver = value;
    }

}
