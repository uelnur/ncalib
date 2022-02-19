package main.java.kz.ncalib.ocsp;

import kz.gov.pki.kalkan.ocsp.OCSPReq;
import kz.gov.pki.kalkan.ocsp.OCSPResp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class OcspClient implements OcspClientInterface {
    private final String ocspUrl;

    public OcspClient(String tspUrl) {
        this.ocspUrl = tspUrl;
    }

    @Override
    public OCSPResp makeRequest(OCSPReq request) throws IOException {
        InputStream rawResponse = makeRawRequest(ocspUrl, request.getEncoded());
        return new OCSPResp(rawResponse);
    }

    protected InputStream makeRawRequest(String url, byte[] request) throws IOException {
        URL oscpUrl = new URL(url);

        HttpURLConnection con = (HttpURLConnection) oscpUrl.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");

        OutputStream reqStream = con.getOutputStream();
        reqStream.write(request);
        reqStream.close();

        con.disconnect();

        return con.getInputStream();
    }
}
