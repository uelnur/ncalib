package main.java.kz.ncalib.cms;

import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.jce.provider.cms.CMSException;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore;
import kz.gov.pki.kalkan.tsp.TSPAlgorithms;
import kz.gov.pki.kalkan.tsp.TSPException;
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo;
import kz.gov.pki.kalkan.util.encoders.Base64;
import kz.gov.pki.kalkan.util.encoders.Hex;
import main.java.kz.ncalib.pki.ChainBuilder;
import main.java.kz.ncalib.tsp.TspVerifier;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

// TODO: требуется большой рефакторинг
public class CmsVerifier {
    private final Provider provider;
    private final TspVerifier tspVerifier;
    private final ChainBuilder chainBuilder;

    public CmsVerifier(Provider provider, TspVerifier tspVerifier, ChainBuilder chainBuilder) {
        this.provider = provider;
        this.tspVerifier = tspVerifier;
        this.chainBuilder = chainBuilder;
    }

    public void verify() throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, CertStoreException, CertificateException, IOException, TSPException, SignatureException, InvalidKeyException {
        boolean checkCrl = true;
        String cmsB64 = "";
        CMSSignedData cms = null;
        byte[] decoded = Base64.decode(cmsB64);

        try {
            cms = new CMSSignedData(decoded);
        } catch (CMSException e) {
            // TODO:
            return;
        }

        SignerInformationStore signers = cms.getSignerInfos();
        String providerName = provider.getName();
        CertStore clientCerts = cms.getCertificatesAndCRLs("Collection", providerName);

        Iterator sit = signers.getSigners().iterator();

        boolean signInfo = false;

        List<X509Certificate> certs = new ArrayList<>();
        List<Boolean> certsSignValid = new ArrayList<>();
        //HashMap<String, ArrayList<JSONObject>> certSerialNumbersToTsps = new HashMap<>();

        while (sit.hasNext()) {
            signInfo = true;

            SignerInformation signer = (SignerInformation) sit.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();

            boolean certCheck = false;
            List<String> certSerialNumbers = new ArrayList<>();

            while (certIt.hasNext()) {
                certCheck = true;
                X509Certificate cert = (X509Certificate) certIt.next();

                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    return;
                    //throw new ApiErrorException(e.getMessage(), HttpURLConnection.HTTP_BAD_REQUEST, ApiStatus.STATUS_CERTIFICATE_INVALID);
                }

                certs.add(cert);
                certsSignValid.add(signer.verify(cert.getPublicKey(), providerName));
                certSerialNumbers.add(String.valueOf(cert.getSerialNumber()));
            }

            if (!certCheck) {
                return;
            }

            // Tsp verification
            Vector<Attribute> tspAttrs = tspVerifier.getSignerTspAttributes(signer);

            for (Attribute attr : tspAttrs) {
                if (attr.getAttrValues().size() != 1) {
                    return;
                    //throw new Exception("Too many TSP tokens");
                }

                CMSSignedData tspCms = new CMSSignedData(attr.getAttrValues().getObjectAt(0).getDERObject().getEncoded());
                TimeStampTokenInfo tokenInfo = tspVerifier.verifyTSP(tspCms);

                String serialNumber = new String(Hex.encode(tokenInfo.getSerialNumber().toByteArray()));
                Date genTime = tokenInfo.getGenTime();
                String tspHashAlgorithm = getHashingAlgorithmByOID(tokenInfo.getMessageImprintAlgOID());
                String hash = new String(Hex.encode(tokenInfo.getMessageImprintDigest()));
            }
        }

        for (int i = 0; i < certs.size(); ++i) {
            X509Certificate cert = certs.get(i);

            // Chain information
            ArrayList<java.security.cert.X509Certificate> chain = null;
            chain = chainBuilder.build(cert);

            if (chain != null) {
                for (java.security.cert.X509Certificate chainCert : chain) {
                    //JSONObject chi = getApiServiceProvider().pki.certInfo(chainCert, false, false, null);
                }
            }

            java.security.cert.X509Certificate issuerCert = null;

            if (chain != null && chain.size() > 1) {
                issuerCert = chain.get(1);
            }

            if (issuerCert == null) {
                return;
            }

        }

    }

    public static String getHashingAlgorithmByOID(String oid) {
        HashMap<String, String> algos = new HashMap<>();

        algos.put(TSPAlgorithms.MD5,"MD5");
        algos.put(TSPAlgorithms.SHA1,"SHA1");
        algos.put(TSPAlgorithms.SHA224,"SHA224");
        algos.put(TSPAlgorithms.SHA256,"SHA256");
        algos.put(TSPAlgorithms.SHA384,"SHA384");
        algos.put(TSPAlgorithms.SHA512,"SHA512");
        algos.put(TSPAlgorithms.RIPEMD128,"RIPEMD128");
        algos.put(TSPAlgorithms.RIPEMD160,"RIPEMD160");
        algos.put(TSPAlgorithms.RIPEMD256,"RIPEMD256");
        algos.put(TSPAlgorithms.GOST34311GT,"GOST34311GT");
        algos.put(TSPAlgorithms.GOST34311,"GOST34311");

        return algos.get(oid);
    }
}
