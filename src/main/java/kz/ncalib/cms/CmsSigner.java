package main.java.kz.ncalib.cms;

import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.tsp.TSPException;
import main.java.kz.ncalib.tsp.TspSigner;
import main.java.kz.ncalib.tsp.TspVerifier;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.stream.Collectors;

// TODO: требуется большой рефакторинг
public class CmsSigner {
    private final Provider provider;
    private final TspSigner tspSigner;
    private final TspVerifier tspVerifier;

    public CmsSigner(Provider provider, TspSigner tspSigner, TspVerifier tspVerifier) {
        this.provider = provider;
        this.tspSigner = tspSigner;
        this.tspVerifier = tspVerifier;
    }

    public CMSSignedData sign(byte[] data, P12[] p12s, boolean withTsp, String tsaPolicy)
            throws KeyStoreException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            CertStoreException,
            CMSException,
            IOException,
            TSPException,
            CertificateException, CMSSignException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        List<X509Certificate> certificates = new ArrayList<>();
        CMSProcessable dataToEncode;

        // Если уже подписанный CMS
        try {
            CMSSignedData signedData = new CMSSignedData(data);

            dataToEncode = signedData.getSignedContent();
            certificates = getCertificatesFromCmsSignedData(signedData);

            SignerInformationStore existingSigners = signedData.getSignerInfos();
            generator.addSigners(existingSigners);
        } catch (CMSException ignored) {
            dataToEncode = new CMSProcessableByteArray(data);
        }

        // Подписываем с каждым ключом
        for (P12 p12 : p12s) {
            signSingle(data, p12.key, p12.password, p12.alias, generator, certificates);
        }

        // Создаем CMS
        CMSSignedData signed = makeSignedData(dataToEncode, certificates, generator);

        // добавляем метку tsp к сформированным подписям
        if (withTsp) {
            signed = addTspAttributes(signed, certificates, tsaPolicy);
        }

        return signed;
    }

    private CMSSignedData makeSignedData(CMSProcessable dataToEncode, List<X509Certificate> certificates, CMSSignedDataGenerator generator) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertStoreException, CMSException {
        List<X509Certificate> uniqueCertificates = certificates.stream().distinct().collect(Collectors.toList());
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(uniqueCertificates);

        CertStore certStore = CertStore.getInstance("Collection", params, provider.getName());
        generator.addCertificatesAndCRLs(certStore);

        return generator.generate(dataToEncode, true, provider.getName());
    }

    private CMSSignedData addTspAttributes(CMSSignedData signed, List<X509Certificate> certificates, String tsaPolicy) throws NoSuchAlgorithmException, TSPException, IOException, NoSuchProviderException {
        String useTsaPolicy = tsaPolicy.equals("TSA_GOSTGT_POLICY") ?
                KNCAObjectIdentifiers.tsa_gostgt_policy.getId() :
                KNCAObjectIdentifiers.tsa_gost_policy.getId();

        SignerInformationStore signerStore = signed.getSignerInfos();
        List<SignerInformation> signers = new ArrayList<>();

        int i = 0;

        for (SignerInformation signer : (Collection<SignerInformation>) signerStore.getSigners()) {
            X509Certificate cert = certificates.get(i++);

            if (tspVerifier.getSignerTspAttributes(signer).isEmpty()) {
                signers.add(tspSigner.addTspToSigner(signer, cert, useTsaPolicy));
            } else {
                signers.add(signer);
            }
        }

        return CMSSignedData.replaceSigners(signed, new SignerInformationStore(signers));
    }

    private void signSingle(byte[] data, byte[] p12String, String password, String alias, CMSSignedDataGenerator generator, List<X509Certificate> certificates) throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeyException, SignatureException, CMSSignException {
        KeyStore p12 = loadKey(p12String, password);
        X509Certificate signerCert = getCertificateFromKeyStore(p12, alias);

        // Получаем закрытый ключ
        PrivateKey privateKey = (PrivateKey) p12.getKey(alias, password.toCharArray());

        Signature sig;
        sig = Signature.getInstance(signerCert.getSigAlgName(), provider.getName());
        sig.initSign(privateKey);
        sig.update(data);

        generator.addSigner(privateKey, signerCert, getDigestAlgorithmOidBYSignAlgorithmOid(signerCert.getSigAlgOID()));
        certificates.add(signerCert);
    }

    private X509Certificate getCertificateFromKeyStore(KeyStore p12, String alias) throws CMSSignException {
        try {

            if (alias == null || alias.isEmpty()) {
                Enumeration<String> als = p12.aliases();

                while (als.hasMoreElements()) {
                    alias = als.nextElement();
                }
            }

            if (!p12.containsAlias(alias)) {
                throw new CMSSignException("certificate_alias_not_found", null);
            }

            X509Certificate cert = (X509Certificate) p12.getCertificate(alias);

            if (cert == null) {
                throw new CMSSignException("certificate_not_found", null);
            }

            cert.checkValidity();
            return cert;
        }
        catch (KeyStoreException e) {
            throw new CMSSignException("key_store_error", e);
        }
        catch (CertificateExpiredException e) {
            throw new CMSSignException("certificate_expired", e);
        }
        catch (CertificateNotYetValidException e ) {
            throw new CMSSignException("certificate_not_yet_valid", e);
        }
    }

    private List<X509Certificate> getCertificatesFromCmsSignedData(CMSSignedData cms) throws CMSSignException {
        try {

            List<X509Certificate> certs = new ArrayList<>();
            SignerInformationStore signers = cms.getSignerInfos();
            String providerName = this.provider.getName();
            CertStore clientCerts = cms.getCertificatesAndCRLs("Collection", providerName);

            for (Object signerObj : signers.getSigners()) {
                SignerInformation signer = (SignerInformation) signerObj;
                X509CertSelector signerConstraints = signer.getSID();
                Collection<? extends Certificate> certCollection = clientCerts.getCertificates(signerConstraints);

                for (Certificate certificate : certCollection) {
                    X509Certificate cert = (X509Certificate) certificate;
                    certs.add(cert);
                }
            }

            return certs;
        }
        catch (NoSuchAlgorithmException e) {
            throw new CMSSignException("algorithm_not_found", e);
        }
        catch (NoSuchProviderException e) {
            throw new CMSSignException("provider_not_found", e);
        }
        catch (CMSException e) {
            throw new CMSSignException("get_certificates_and_crls_error", e);
        }
        catch (CertStoreException e) {
            throw new CMSSignException("get_certificates_error", e);
        }
    }

    private static String getDigestAlgorithmOidBYSignAlgorithmOid(String signOid) {
        if (signOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return CMSSignedDataGenerator.DIGEST_SHA1;
        } else if (signOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return CMSSignedDataGenerator.DIGEST_SHA256;
        } else {
            return CMSSignedDataGenerator.DIGEST_GOST34311_95;
        }
    }

    private KeyStore loadKey(byte[] p12, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
        KeyStore store = KeyStore.getInstance("PKCS12", provider.getName());

        ByteArrayInputStream bs = new ByteArrayInputStream(p12);
        store.load(bs, password.toCharArray());
        bs.close();

        return store;
    }
}
