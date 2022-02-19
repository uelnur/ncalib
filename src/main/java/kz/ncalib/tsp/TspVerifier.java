package main.java.kz.ncalib.tsp;

import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSException;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.TSPException;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

// TODO: Требуется рефакторинг
public class TspVerifier {
    public Vector<Attribute> getSignerTspAttributes(SignerInformation signer) {
        Vector<Attribute> tspAttrs = new Vector<>();

        if (signer.getUnsignedAttributes() == null) {
            return tspAttrs;
        }

        Hashtable attrs = signer.getUnsignedAttributes().toHashtable();

        if (attrs == null || !attrs.containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
            return tspAttrs;
        }

        // в подписи может быть один или несколько tsp атрибутов
        Object attrOrAttrs = attrs.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);

        if (attrOrAttrs instanceof Attribute) {
            tspAttrs.add((Attribute) attrOrAttrs);
        } else {
            tspAttrs = (Vector<Attribute>) attrOrAttrs;
        }

        return tspAttrs;
    }

    public TimeStampTokenInfo verifyTSP(CMSSignedData data) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException, TSPException, CertStoreException, CertificateNotYetValidException, CertificateExpiredException {
        TimeStampToken token = new TimeStampToken(data);
        X509CertSelector signerConstraints = token.getSID();
        CertStore certs = data.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
        Collection<?> certCollection = certs.getCertificates(signerConstraints);
        Iterator<?> certIt = certCollection.iterator();
        X509Certificate cert;

        if (!certIt.hasNext()) {
            throw new TSPException("Validating certificate not found");
        }

        cert = (X509Certificate) certIt.next();
        token.validate(cert, KalkanProvider.PROVIDER_NAME);

        return token.getTimeStampInfo();
    }
}
