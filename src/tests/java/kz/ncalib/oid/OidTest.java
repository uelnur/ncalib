package tests.java.kz.ncalib.oid;

import main.java.kz.ncalib.oid.Oid;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class OidTest {
    @Test
    public void testOid() {
        Oid oid = new Oid("ru");

        assertEquals(oid.get("1.2.398"), "Удостоверяющий центр");

        oid = new Oid("kz");

        assertEquals(oid.get("1.2.398"), "Куәландырушы орталық");
    }
}
