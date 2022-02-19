package main.java.kz.ncalib.crl;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

public interface CrlDownloaderInterface {
    public X509CRL download(String url) throws IOException, CRLException;
}
