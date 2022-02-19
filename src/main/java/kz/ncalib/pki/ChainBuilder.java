package main.java.kz.ncalib.pki;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

/**
 * Строит цепочку сертификатов и проверяет его на правильность
 */
public class ChainBuilder {
    private final CAStore issuersCertStore;

    public ChainBuilder(CAStore issuersCertStore) {
        this.issuersCertStore = issuersCertStore;
    }

    public ArrayList<X509Certificate> build(X509Certificate cert) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
        ArrayList<X509Certificate> result = new ArrayList<>();

        X509Certificate lastCert = cert;
        X509Certificate issuerCert;
        result.add(lastCert);

        // Построение цепочки доверенных сертификатов и их проверка
        do {
            issuerCert = getIssuerCertFromStore(lastCert, issuersCertStore.getTrustedCertStore());

            if ( issuerCert == null ) {
                break;
            }

            verify(lastCert, issuerCert);
            lastCert = issuerCert;

            if (!result.contains(lastCert)) {
                result.add(lastCert);
            }

        } while (true);

        issuerCert = getIssuerCertFromStore(lastCert, issuersCertStore.getRootCertStore());

        // Если не найден корневой сертификат, цепочке нельзя доверять
        if ( issuerCert == null ) {
            return null;
        }

        // Добавление в цепочку корневого сертификата и его проверка
        verify(lastCert, issuerCert);
        result.add(issuerCert);
        return result;
    }

    protected X509Certificate getIssuerCertFromStore(X509Certificate cert, ArrayList<X509Certificate> certStore) {
        if (cert.getIssuerDN().equals(cert.getSubjectDN())) return null;

        for (X509Certificate item : certStore) {
            if (cert.getIssuerDN().equals(item.getSubjectDN())) {
                return item;
            }
        }

        return null;
    }

    protected void verify(X509Certificate cert, X509Certificate issuerCert) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        // Проверка сертификата по публичному ключу издателя
        cert.verify(issuerCert.getPublicKey());

        // Проверка валидности сертификата издателя, на момент выпуска сертификата
        Date certIssuedDate = cert.getNotBefore(); // В качестве даты выпуска сертификата берем срок начала действия
        issuerCert.checkValidity(certIssuedDate);
    }
}
