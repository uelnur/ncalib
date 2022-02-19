package main.java.kz.ncalib.tsp;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.tsp.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class TspFactory {
    private final TspClientInterface tspClient;

    public TspFactory(TspClientInterface tspClient) {
        this.tspClient = tspClient;
    }

    public TimeStampToken create(byte[] data, String hashAlg, String reqPolicy) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, TSPException {

        // Генерация хэш данных
        byte[] hash = generateDataHash(data, hashAlg);

        // Создание TSP запроса
        TimeStampRequest request = generateTspRequest(hash, hashAlg, reqPolicy);

        // Получение TSP ответа
        TimeStampResponse response = tspClient.makeRequest(request);

        return response.getTimeStampToken();
    }

    private TimeStampRequest generateTspRequest(byte[] hash, String hashAlg, String reqPolicy) {
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        reqGen.setReqPolicy(reqPolicy);

        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

        return reqGen.generate(hashAlg, hash, nonce);
    }

    private byte[] generateDataHash(byte[] data, String hashAlg) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance(hashAlg, KalkanProvider.PROVIDER_NAME);
        md.update(data);

        return md.digest();
    }
}
