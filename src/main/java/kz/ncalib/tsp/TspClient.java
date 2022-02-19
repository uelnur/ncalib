package main.java.kz.ncalib.tsp;

import kz.gov.pki.kalkan.tsp.TSPException;
import kz.gov.pki.kalkan.tsp.TimeStampRequest;
import kz.gov.pki.kalkan.tsp.TimeStampResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class TspClient implements TspClientInterface {
    private final String tspUrl;

    public TspClient(String tspUrl) {
        this.tspUrl = tspUrl;
    }

    public TimeStampResponse makeRequest(TimeStampRequest request) throws IOException, TSPException {
        InputStream rawResponse = makeRawRequest(tspUrl, request.getEncoded());
        TimeStampResponse response = new TimeStampResponse(rawResponse);
        response.validate(request);

        return response;
    }

    protected InputStream makeRawRequest(String url, byte[] request) throws IOException {
        URL tspUrl = new URL(url);

        HttpURLConnection con = (HttpURLConnection) tspUrl.openConnection();
        con.setRequestMethod("POST");
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", "application/timestamp-query");

        OutputStream reqStream = con.getOutputStream();
        reqStream.write(request);
        reqStream.close();

        con.disconnect();
        return con.getInputStream();
    }
}
