package main.java.kz.ncalib.tsp;

import kz.gov.pki.kalkan.asn1.*;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.TSPAlgorithms;
import kz.gov.pki.kalkan.tsp.TSPException;
import kz.gov.pki.kalkan.tsp.TimeStampToken;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

// TODO: Требуется рефакторинг
public class TspSigner {
    private final TspFactory tspFactory;

    public TspSigner(TspFactory tspFactory) {
        this.tspFactory = tspFactory;
    }

    public SignerInformation addTspToSigner(SignerInformation signer, X509Certificate cert, String useTsaPolicy) throws NoSuchAlgorithmException, NoSuchProviderException, TSPException, IOException {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        ASN1EncodableVector vector = new ASN1EncodableVector();

        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        TimeStampToken tsp = tspFactory.create(signer.getSignature(), getTspHashAlgorithmByOid(cert.getSigAlgOID()), useTsaPolicy);
        byte[] ts = tsp.getEncoded();
        ASN1Encodable signatureTimeStamp = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(byteToASN1(ts)));
        vector.add(signatureTimeStamp);

        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(vector));
    }

    public static String getTspHashAlgorithmByOid(String signOid) {
        if (signOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA1;
        }
        else if (signOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA256;
        }
        else {
            return TSPAlgorithms.GOST34311;
        }
    }

    public static DERObject byteToASN1(byte[] data) throws IOException {
        try (ASN1InputStream in = new ASN1InputStream(data)) {
            return in.readObject();
        }
    }
}
