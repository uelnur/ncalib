package main.java.kz.ncalib.crl;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

public class CrlClient implements CrlDownloaderInterface {
    private final CertificateFactory crlFactory = CertificateFactory.getInstance("X.509");

    public CrlClient() throws CertificateException {
    }

    @Override
    public X509CRL download(String url) throws IOException, CRLException {
        URL crlUrl = new URL(url);

        HttpURLConnection con = (HttpURLConnection) crlUrl.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");

        InputStream stream = con.getInputStream();
        con.disconnect();

        return (X509CRL) crlFactory.generateCRL(stream);
    }
}
