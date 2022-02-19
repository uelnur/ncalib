package main.java.kz.ncalib.oid;

import java.util.Objects;

public class Oid implements OidTranslationInterface {
    public OidTranslationInterface oidTranslation;

    public Oid(String lang) {
        if (Objects.equals(lang, "kz")) {
            oidTranslation = new OidKz();
        }

        if (Objects.equals(lang, "ru")) {
            oidTranslation = new OidRu();
        }
    }

    public String get(String oid) {
        return oidTranslation.get(oid);
    }
}
