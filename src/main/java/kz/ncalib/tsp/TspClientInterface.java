package main.java.kz.ncalib.tsp;

import kz.gov.pki.kalkan.tsp.TSPException;
import kz.gov.pki.kalkan.tsp.TimeStampRequest;
import kz.gov.pki.kalkan.tsp.TimeStampResponse;

import java.io.IOException;

public interface TspClientInterface {
    public TimeStampResponse makeRequest(TimeStampRequest request) throws IOException, TSPException;
}
