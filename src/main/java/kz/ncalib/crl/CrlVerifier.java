package main.java.kz.ncalib.crl;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Map;

public class CrlVerifier {
    public static class CrlRevocation {
        public String url;
        public X509CRL crl;
        public X509CRLEntry crlEntry;

        public CrlRevocation(X509CRL crl, X509CRLEntry crlEntry, String url) {
            this.crl = crl;
            this.crlEntry = crlEntry;
            this.url = url;
        }
    }

    private final CrlContainer crlContainer;

    public CrlVerifier(CrlContainer crlContainer) {
        this.crlContainer = crlContainer;
    }

    public CrlRevocation verify(X509Certificate cert) {
        for (Map.Entry<String, X509CRL> crlEntry: crlContainer.getContainer().entrySet()) {
            X509CRL crl = crlEntry.getValue();
            String url = crlEntry.getKey();

            if (crl.isRevoked(cert)) {
                X509CRLEntry entry = crl.getRevokedCertificate(cert);

                return new CrlRevocation(crl, entry, url);
            }
        }

        return null;
    }
}
