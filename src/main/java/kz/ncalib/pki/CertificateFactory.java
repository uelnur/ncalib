package main.java.kz.ncalib.pki;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Служит для построения объекта сертификата
 */
public class CertificateFactory {
    private final java.security.cert.CertificateFactory factory;

    public CertificateFactory(String providerName) throws CertificateException, NoSuchProviderException {
        factory = java.security.cert.CertificateFactory.getInstance("X.509", providerName);
    }

    public X509Certificate generate(InputStream stream) throws CertificateException, NoSuchProviderException, IOException {
        X509Certificate cert = (X509Certificate)factory.generateCertificate(stream);
        stream.close();
        return cert;
    }

    public X509Certificate generate(File file) throws CertificateException, NoSuchProviderException, IOException {
        FileInputStream stream = new FileInputStream(file.getAbsolutePath());

        return generate(stream);
    }

    public X509Certificate generate(String file) throws CertificateException, NoSuchProviderException, IOException {
        FileInputStream stream = new FileInputStream(file);

        return generate(stream);
    }

    public X509Certificate generate(byte[] cert) throws CertificateException, NoSuchProviderException, IOException {
        ByteArrayInputStream stream = new ByteArrayInputStream(cert);

        return generate(stream);
    }
}
