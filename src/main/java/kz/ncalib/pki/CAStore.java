package main.java.kz.ncalib.pki;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Хранилище корневых и доверенных сертификатов
 */
public class CAStore {
    private final CertificateFactory factory;

    private final ArrayList<X509Certificate> root = new ArrayList<>();
    private final ArrayList<X509Certificate> trusted = new ArrayList<>();

    public CAStore(CertificateFactory factory) {
        this.factory = factory;
    }

    public void addRootCertificateFromFile(File file) throws CertificateException, IOException, NoSuchProviderException {
        X509Certificate x509 = factory.generate(file);

        addRootCertificate(x509);
    }

    public void addRootCertificate(X509Certificate x509) {
        root.add(x509);
    }

    public void addTrustedCertificateFromFile(File file) throws CertificateException, IOException, NoSuchProviderException {
        X509Certificate x509 = factory.generate(file);

        addTrustedCertificate(x509);
    }

    public void addTrustedCertificate(X509Certificate x509) {
        trusted.add(x509);
    }

    public ArrayList<X509Certificate> getRootCertStore() {
        return root;
    }

    public ArrayList<X509Certificate> getTrustedCertStore() {
        return trusted;
    }
}
