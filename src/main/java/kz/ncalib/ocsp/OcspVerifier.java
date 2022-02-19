package main.java.kz.ncalib.ocsp;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.ocsp.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Hashtable;

// TODO: требуется рефакторинг
// TODO: добавить проверку нескольких сертификатов
public class OcspVerifier {
    private final Provider provider;
    private final OcspClientInterface ocspClient;

    public OcspVerifier(Provider provider, OcspClientInterface ocspClient) {
        this.provider = provider;
        this.ocspClient = ocspClient;
    }

    public CertificateStatus verify(X509Certificate cert, X509Certificate issuerCert) throws IOException, OCSPException {
        byte[] nonce = generateOcspNonce();

        OCSPReq request = buildOcspRequest(cert.getSerialNumber(), issuerCert, CertificateID.HASH_SHA256, nonce);
        OCSPResp response = ocspClient.makeRequest(request);

        return processOcspResponse(response, nonce);
    }

    private byte[] generateOcspNonce() {
        byte[] nonce = new byte[8];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(nonce);

        return nonce;
    }

    private CertificateStatus processOcspResponse(OCSPResp resp, byte[] nonce) throws IOException, OCSPException {
        if (resp.getStatus() != 0) {
            // TODO: проверить нулевой статус
            return null;
        }

        BasicOCSPResp brep = (BasicOCSPResp) resp.getResponseObject();
        byte[] respNonceExt = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());

        if (respNonceExt != null) {
            ASN1InputStream asn1In = new ASN1InputStream(respNonceExt);
            DERObject derObj = asn1In.readObject();
            asn1In.close();
            byte[] extV = DEROctetString.getInstance(derObj).getOctets();
            asn1In = new ASN1InputStream(extV);
            derObj = asn1In.readObject();
            asn1In.close();

            if (!Arrays.equals(nonce, DEROctetString.getInstance(derObj).getOctets())) {
                throw new OCSPException("Nonce aren't equals.");
            }
        }

        SingleResp[] singleResps = brep.getResponses();
        SingleResp singleResp = singleResps[0];

        return (CertificateStatus) singleResp.getCertStatus();
    }

    private OCSPReq buildOcspRequest(BigInteger serialNumber, X509Certificate issuerCert, String hashAlg, byte[] nonce) throws OCSPException {
        OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();

        CertificateID certId = new CertificateID(hashAlg, issuerCert, serialNumber, provider.getName());

        ocspReqGenerator.addRequest(certId);

        Hashtable x509Extensions = new Hashtable();

        // добавляем nonce
        x509Extensions.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, new X509Extension(false, new DEROctetString(new DEROctetString(nonce))) {
        });
        ocspReqGenerator.setRequestExtensions(new X509Extensions(x509Extensions));

        return ocspReqGenerator.generate();
    }
}
