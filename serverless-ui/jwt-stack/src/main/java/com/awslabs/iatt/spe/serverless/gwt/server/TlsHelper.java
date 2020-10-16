package com.awslabs.iatt.spe.serverless.gwt.server;

import io.vavr.Tuple2;
import io.vertx.core.net.JksOptions;

import javax.servlet.ServletContext;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public interface TlsHelper {
    char[] BLANK_PASSWORD = "".toCharArray();

    Tuple2<KeyStore, File> getRandomKeystore(String name) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException;

    Tuple2<KeyStore, File> getFixedKeystore(ServletContext servletContext, String name) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException;

    Tuple2<KeyStore, File> getKeystoreForKeyPair(KeyPair keyPair, String prefix) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException;

    KeyPair getRandomKeypair();

    void writeKeyPair(String prefix, KeyPair keyPair);

    KeyPair readKeyPair(ServletContext servletContext, String prefix);

    KeyPair decodeKeyPair(byte[] encodedPublicKey, byte[] encodedPrivateKey);

    KeyPair getFixedKeypair(ServletContext servletContext);

    X509Certificate getCertFromKeyPair(KeyPair keyPair, String name) throws SignatureException, InvalidKeyException;

    Void writeCertToFile(X509Certificate x509Certificate, String prefix) throws IOException, CertificateEncodingException;

    JksOptions getRandomJksOptions(String name) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, IOException;

    JksOptions getFixedJksOptions(ServletContext servletContext, String name) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, IOException;

    JksOptions getJksOptionsForKeyPair(KeyPair keyPair, String prefix) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, IOException;

    String getKeyString(RSAPublicKey publicKey);
}
