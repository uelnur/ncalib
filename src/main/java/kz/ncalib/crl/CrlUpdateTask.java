package main.java.kz.ncalib.crl;

import java.io.IOException;
import java.security.cert.CRLException;
import java.util.TimerTask;

public class CrlUpdateTask extends TimerTask {
    public String url;
    public CrlContainer container;

    public CrlUpdateTask(String url, CrlContainer container) {
        this.url = url;
        this.container = container;
    }

    @Override
    public void run() {
        try {
            container.fetchUrl(url);
        } catch (IOException | CRLException e) {
            e.printStackTrace();
        }
    }
}
