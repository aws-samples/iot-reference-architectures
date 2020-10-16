package com.awslabs.iatt.spe.serverless.gwt.server;

import io.vavr.Tuple2;
import io.vavr.control.Option;
import io.vavr.control.Try;
import io.vertx.core.net.JksOptions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Optional;

public class BasicTlsHelper implements TlsHelper {
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final Logger log = LoggerFactory.getLogger(BasicTlsHelper.class);
    private Option<KeyPair> fixedKeyPair = Option.none();

    @Override
    public Tuple2<KeyStore, File> getRandomKeystore(String name) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        return getKeystore(Optional.empty(), getRandomKeypair(), name);
    }

    @Override
    public Tuple2<KeyStore, File> getFixedKeystore(ServletContext servletContext, String name) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        return getKeystore(Optional.empty(), getFixedKeypair(servletContext), name);
    }

    @Override
    public Tuple2<KeyStore, File> getKeystoreForKeyPair(KeyPair keyPair, String prefix) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        return getKeystore(Optional.empty(), keyPair, prefix);
    }

    @Override
    public KeyPair getRandomKeypair() {
        KeyPairGenerator keyPairGenerator = Try.of(() -> KeyPairGenerator.getInstance("RSA")).get();
        keyPairGenerator.initialize(4096, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;
    }

    @Override
    public void writeKeyPair(String prefix, KeyPair keyPair) {
        String privateKeyFilename = getPrivateKeyFilename(prefix);
        log.info("Writing private key [{}]", privateKeyFilename);

        // Throw exception on failure
        Try.withResources(() -> new JcaPEMWriter(new FileWriter(privateKeyFilename)))
                .of(writer -> writeObject(writer, keyPair.getPrivate()))
                .get();

        String publicKeyFilename = getPublicKeyFilename(prefix);
        log.info("Writing public key [{}]", publicKeyFilename);

        // Throw exception on failure
        Try.withResources(() -> new JcaPEMWriter(new FileWriter(publicKeyFilename)))
                .of(writer -> writeObject(writer, keyPair.getPublic()))
                .get();
    }

    private Void writeObject(JcaPEMWriter writer, Object object) throws IOException {
        writer.writeObject(object);
        return null;
    }

    private String getPublicKeyFilename(String prefix) {
        return String.join("-", prefix, "public.key");
    }

    private String getPrivateKeyFilename(String prefix) {
        return String.join("-", prefix, "private.key");
    }

    private String getCertFilename(String prefix) {
        return String.join(".", prefix, "crt", "pem");
    }

    @Override
    public KeyPair readKeyPair(ServletContext servletContext, String prefix) {
        String privateKeyFilename = getPrivateKeyFilename(prefix);

        Option<InputStream> inputStreamOption = getResourceInLambdaEnvironment(privateKeyFilename);

        if (inputStreamOption.isEmpty()) {
            inputStreamOption = Try.of(() -> getResourceInLocalEnvironment(servletContext, privateKeyFilename)).get();
        }

        if (inputStreamOption.isEmpty()) {
            throw new RuntimeException("File not found [" + privateKeyFilename + "]");
        }

        InputStreamReader inputStreamReader = new InputStreamReader(inputStreamOption.get());

        PEMKeyPair pemKeyPair = (PEMKeyPair) Try.withResources(() -> new PEMParser(inputStreamReader))
                .of(PEMParser::readObject)
                .get();

        return Try.of(() -> new JcaPEMKeyConverter().getKeyPair(pemKeyPair)).get();
    }

    private Option<InputStream> getResourceInLambdaEnvironment(String filename) {
        return Option.of(getClass().getClassLoader().getResourceAsStream(filename));
    }

    private Option<InputStream> getResourceInLocalEnvironment(ServletContext servletContext, String filename) throws MalformedURLException {
        return Option.of(servletContext.getResource(filename))
                .map(url -> Try.of(url::openStream).getOrNull());
    }

    @Override
    public KeyPair decodeKeyPair(byte[] encodedPublicKey, byte[] encodedPrivateKey) {
        byte[] binaryPublicKey = Base64.decode(encodedPublicKey);
        byte[] binaryPrivateKey = Base64.decode(encodedPrivateKey);

        KeyFactory keyFactory = Try.of(() -> KeyFactory.getInstance("RSA")).get();
        RSAPrivateKey privateKey = Try.of(() -> (RSAPrivateKey) keyFactory.generatePrivate(new X509EncodedKeySpec(binaryPrivateKey))).get();
        RSAPublicKey publicKey = Try.of(() -> (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(binaryPublicKey))).get();

        return new KeyPair(publicKey, privateKey);
    }

    private byte[] readFile(File file) {
        return Try.of(() -> Files.readAllBytes(file.toPath())).get();
    }

    private void writeFile(File file, byte[] contents) {
        Try.withResources(() -> new FileOutputStream(file))
                .of(fileOutputStream -> writeFile(fileOutputStream, contents))
                .get();
    }

    private Void writeFile(FileOutputStream fileOutputStream, byte[] contents) throws IOException {
        fileOutputStream.write(contents);

        return null;
    }

    @Override
    public KeyPair getFixedKeypair(ServletContext servletContext) {
        if (fixedKeyPair.isEmpty()) {
            fixedKeyPair = Option.of(readKeyPair(servletContext, "fixed"));
        }

        return fixedKeyPair.get();
    }

    private Tuple2<KeyStore, File> getKeystore(Optional<File> optionalTempFile, KeyPair keyPair, String prefix) throws SignatureException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        X509Certificate cert;

        File certFile = new File(getCertFilename(prefix));

        if (!certFile.exists()) {
            log.info("Creating new self-signed certificate");
            // GENERATE THE X509 CERTIFICATE
            cert = getCertFromKeyPair(keyPair, prefix);
        } else {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            log.info("Using existing certificate [{}]", certFile.getName());
            InputStream in = new ByteArrayInputStream(readFile(certFile));
            cert = (X509Certificate) certFactory.generateCertificate(in);
        }

        return getKeystore(optionalTempFile, keyPair, cert);
    }

    private Tuple2<KeyStore, File> getKeystore(Optional<File> optionalTempFile, KeyPair keyPair, java.security.cert.Certificate cert) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        File tempFile = optionalTempFile.orElseGet(this::getTempFile);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("", keyPair.getPrivate(), BLANK_PASSWORD, new java.security.cert.Certificate[]{cert});

        keyStore.store(new FileOutputStream(tempFile), BLANK_PASSWORD);
        return new Tuple2<>(keyStore, tempFile);
    }

    @Override
    public X509Certificate getCertFromKeyPair(KeyPair keyPair, String name) throws SignatureException, InvalidKeyException {
        X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v3CertGen.setIssuerDN(new X509Principal("CN=" + name));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10)));
        v3CertGen.setSubjectDN(new X509Principal("CN=" + name));
        v3CertGen.setPublicKey(keyPair.getPublic());
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        return v3CertGen.generateX509Certificate(keyPair.getPrivate());
    }

    @Override
    public Void writeCertToFile(X509Certificate x509Certificate, String prefix) throws IOException, CertificateEncodingException {
        // Split the base64 encoded cert into lines, max. 64 characters per line
        String encodedString = new String(Base64.encode(x509Certificate.getEncoded()));
        encodedString = encodedString.replaceAll("(.{64})", "$1\n");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(BEGIN_CERT.getBytes());
        baos.write("\n".getBytes());
        baos.write(encodedString.getBytes());
        baos.write("\n".getBytes());
        baos.write(END_CERT.getBytes());
        baos.write("\n".getBytes());

        String certFilename = getCertFilename(prefix);
        log.info("Writing cert [{}]", certFilename);
        writeFile(new File(certFilename), baos.toByteArray());

        return null;
    }

    @Override
    public JksOptions getRandomJksOptions(String name) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, IOException {
        Tuple2<KeyStore, File> randomKeyStore = getRandomKeystore(name);
        return new JksOptions().setPassword(String.valueOf(BLANK_PASSWORD)).setPath(randomKeyStore._2.getAbsolutePath());
    }

    @Override
    public JksOptions getFixedJksOptions(ServletContext servletContext, String name) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, IOException {
        Tuple2<KeyStore, File> fixedKeyStore = getFixedKeystore(servletContext, name);
        return new JksOptions().setPassword(String.valueOf(BLANK_PASSWORD)).setPath(fixedKeyStore._2.getAbsolutePath());
    }

    @Override
    public JksOptions getJksOptionsForKeyPair(KeyPair keyPair, String prefix) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, IOException {
        Tuple2<KeyStore, File> fixedKeyStore = getKeystoreForKeyPair(keyPair, prefix);
        return new JksOptions().setPassword(String.valueOf(BLANK_PASSWORD)).setPath(fixedKeyStore._2.getAbsolutePath());
    }

    private File getTempFile() {
        return Try.of(() -> {
            File tempFile = File.createTempFile("temp", "jks");
            tempFile.deleteOnExit();

            return tempFile;
        }).get();
    }

    @Override
    public String getKeyString(RSAPublicKey publicKey) {
        String keyString = String.join("-",
                publicKey.getPublicExponent().toString(36),
                publicKey.getModulus().toString(36));

        if (keyString.length() > 800) {
            throw new RuntimeException("Key string is too long to fit into an attribute");
        }

        return keyString;
    }
}