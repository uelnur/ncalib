package tests.java.kz.ncalib.pki;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import main.java.kz.ncalib.pki.CertificateFactory;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

public class CAStoreTest {
    @Test
    public void checkFactoryNotFailsOnConstruct() {
        Provider provider = new KalkanProvider();
        Security.addProvider(provider);
        assertDoesNotThrow(() ->
            new CertificateFactory(KalkanProvider.PROVIDER_NAME)
        );
    }

    @Test
    public void checkGenerate() {
        Provider provider = new KalkanProvider();
        Security.addProvider(provider);

        assertDoesNotThrow(() -> {
            CertificateFactory factory = new CertificateFactory(KalkanProvider.PROVIDER_NAME);
            File file = new File("./src/tests/resources/certs/root/root_gost.crt");
            X509Certificate cert = factory.generate(file);

            assertInstanceOf(X509Certificate.class, cert);
            assertEquals("ECGOST34310", cert.getSigAlgName());

            file = new File("./src/tests/resources/certs/root/root_rsa.crt");
            cert = factory.generate(file);

            assertInstanceOf(X509Certificate.class, cert);
            assertEquals("SHA256WithRSAEncryption", cert.getSigAlgName());
        });

        assertDoesNotThrow(() -> {
            CertificateFactory factory = new CertificateFactory(KalkanProvider.PROVIDER_NAME);
            X509Certificate cert = factory.generate("./src/tests/resources/certs/root/root_gost.crt");

            assertInstanceOf(X509Certificate.class, cert);
            assertEquals("ECGOST34310", cert.getSigAlgName());

            cert = factory.generate("./src/tests/resources/certs/root/root_rsa.crt");

            assertInstanceOf(X509Certificate.class, cert);
            assertEquals("SHA256WithRSAEncryption", cert.getSigAlgName());
        });
    }

}
