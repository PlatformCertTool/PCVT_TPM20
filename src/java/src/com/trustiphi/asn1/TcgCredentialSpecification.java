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

package com.trustiphi.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;

/**
 *    ASN1 structure.
 * 
 * 
 * tCGCredentialSpecification ATTRIBUTE ::= {
 *    WITH SYNTAX TCGSpecificationVersion
 *    ID tcg-at-tcgCredentialSpecification }
 *
 * TCGSpecificationVersion ::= SEQUENCE {
 *    majorVersion INTEGER,
 *    minorVersion INTEGER,
 *    revision INTEGER }
 *
 * 
 */
public class TcgCredentialSpecification extends Asn1Translator {
    private Integer majorVersion=null;
    private Integer minorVersion=null;
    private Integer revision=null;
    
    /**
     * Create an empty TcgCredentialSpecification
     */
    public TcgCredentialSpecification() {
    }
    
    /**
     * Create an TcgCredentialSpecification with input values
     */
    public TcgCredentialSpecification(Integer majorVersion, Integer minorVersion, Integer revision) {
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.revision = revision;
    }
    
    /**
     * Create a TcgCredentialSpecification from an ASN1Sequence.
     * The ASN1Sequence should be formatted correctly and contain the correct information.
     * If it is missing information it is not assigned.  If an unexpected format is encountered
     * an IOException is thrown.
     * 
     * The expected format is:
     * 
     *  ASN1Sequence
     *      majorVersion (ASN1Integer)
     *      minorVersion (ASN1Integer)
     *      revision (ASN1Interger)
     * 
     * @param tcgCredentialSpecEncodable
     * @throws IOException if unexpected ASN1 formatting is encountered 
     */
    public TcgCredentialSpecification(ASN1Encodable tcgCredentialSpecEncodable) 
            throws IOException 
    {
        if(tcgCredentialSpecEncodable instanceof ASN1Sequence)
        {
            ASN1Sequence tcgCredentialSpec = (ASN1Sequence) tcgCredentialSpecEncodable;
            if(tcgCredentialSpec.size() > 0)
            {
                ASN1Encodable[] version_array = tcgCredentialSpec.toArray();
                if(version_array.length > 0)
                {
                    if(version_array[0] instanceof ASN1Integer)
                    {
                        this.majorVersion = new Integer(((ASN1Integer)version_array[0]).getValue().intValue()); 
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing TcgCredentialSpecification.majorVersion. Expected ASN1Integer; Found " 
                                        + version_array[0].getClass().toString());
                    }
                }
                if(version_array.length > 1)
                {
                    if(version_array[1] instanceof ASN1Integer)
                    {
                        this.minorVersion = new Integer(((ASN1Integer)version_array[1]).getValue().intValue()); 
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing TcgCredentialSpecification.minorVersion. Expected ASN1Integer; Found " 
                                        + version_array[1].getClass().toString());
                    }
                }
                if(version_array.length > 2)
                {
                    if(version_array[2] instanceof ASN1Integer)
                    {
                        this.revision = new Integer(((ASN1Integer)version_array[2]).getValue().intValue()); 
                    }
                    else {
                        // unexpected type
                        throw new IOException(
                                "Unexpected ASN1 formatting while parsing TcgCredentialSpecification.revision. Expected ASN1Integer; Found " 
                                        + version_array[2].getClass().toString());
                    }
                }
            }            
        }
        else {
            // unexpected type
            throw new IOException(
                    "Unexpected ASN1 formatting while parsing TcgCredentialSpecification. Expected ASN1Seqeunce; Found " 
                            + tcgCredentialSpecEncodable.getClass().toString());
        }
    }
    
    /* (non-Javadoc)
     * 
     *  DLSequence
     *      majorVersion (ASN1Integer)
     *      minorVersion (ASN1Integer)
     *      revision (ASN1Interger)
     * 
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1Encodable[] asn1EncodableArr = new ASN1Encodable[3];
        asn1EncodableArr[0] = asn1EncodableArr[1] = asn1EncodableArr[2] = null;
        if(majorVersion != null) {
            asn1EncodableArr[0] = new ASN1Integer(majorVersion.longValue());
        }
        if(minorVersion != null) {
            asn1EncodableArr[1] = new ASN1Integer(minorVersion.longValue());
        }
        if(revision != null) {
            asn1EncodableArr[2] = new ASN1Integer(revision.longValue());
        }
        DLSequence asn1_platformSpec = new DLSequence(asn1EncodableArr);

        return asn1_platformSpec;
    }

    /**
     * @return the majorVersion
     */
    public Integer getMajorVersion() {
        return majorVersion;
    }

    /**
     * @param majorVersion the majorVersion to set
     */
    public void setMajorVersion(Integer majorVersion) {
        this.majorVersion = majorVersion;
    }

    /**
     * @return the minorVersion
     */
    public Integer getMinorVersion() {
        return minorVersion;
    }

    /**
     * @param minorVersion the minorVersion to set
     */
    public void setMinorVersion(Integer minorVersion) {
        this.minorVersion = minorVersion;
    }

    /**
     * @return the revision
     */
    public Integer getRevision() {
        return revision;
    }

    /**
     * @param revision the revision to set
     */
    public void setRevision(Integer revision) {
        this.revision = revision;
    }

}
