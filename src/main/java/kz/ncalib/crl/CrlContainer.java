package main.java.kz.ncalib.crl;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CrlContainer {
    private final Map<String, X509CRL> container = new ConcurrentHashMap<>();

    private final String[] urls;
    private final HashMap<String, Timer> timers;
    private final CrlDownloaderInterface downloader;

    public CrlContainer(String[] urls, CrlDownloaderInterface downloader) throws CertificateException {
        this.urls = urls;
        this.downloader = downloader;
        timers = new HashMap<>();
    }

    public Map<String, X509CRL> getContainer() {
        return container;
    }

    public void fetchUrls() throws CertificateException, IOException, CRLException {
        for (String url: urls) {
            fetchUrl(url);
        }
    }

    public void fetchUrl(String url) throws IOException, CRLException {
        X509CRL crl = downloader.download(url);
        container.put(url, crl);

        setTimer(url, crl);
    }

    // Установка задачи на обновление CRL по его дате устаревания
    private void setTimer(String url, X509CRL crl) {
        Timer timer;
        timer = timers.get(url);

        if (timer != null) {
            timer.cancel();
            timer.purge();
        }

        timer = new Timer(true);
        Date nextUpdateTime = crl.getNextUpdate();

        if ( nextUpdateTime == null ) {
            nextUpdateTime = crl.getThisUpdate();

            if ( nextUpdateTime == null ) {
                nextUpdateTime = new Date();
            }

            Calendar cal = Calendar.getInstance();
            cal.setTime(nextUpdateTime);
            cal.add(Calendar.DATE, 1);
            nextUpdateTime = cal.getTime();
        }

        timer.schedule(new CrlUpdateTask(url, this), nextUpdateTime);

        timers.put(url, timer);
    }
}
