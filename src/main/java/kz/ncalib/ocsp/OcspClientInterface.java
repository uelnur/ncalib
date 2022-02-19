package main.java.kz.ncalib.ocsp;

import kz.gov.pki.kalkan.ocsp.OCSPReq;
import kz.gov.pki.kalkan.ocsp.OCSPResp;

import java.io.IOException;

public interface OcspClientInterface {
    public OCSPResp makeRequest(OCSPReq request) throws IOException;
}
