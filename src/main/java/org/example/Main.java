package org.example;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class Main {
    public static void main(String[] args) {
//    ArgumentParser parser = ArgumentParsers.newFor("CSR Signing").build()
//      .description("Get a CSR signed with a step-ca server.");
//    parser.addArgument("ca_url").type(String.class).help("The step-ca URL");
//    parser.addArgument("ca_fingerprint").type(String.class).help("The CA fingerprint");
//    parser.addArgument("provisioner_name").type(String.class).help("The CA JWK provisioner to use");
//    parser.addArgument("jwk_filename").type(String.class).help("The JWK private key filename (JSON formatted)");
//
//    try {
//      Namespace ns = parser.parseArgs(args);
//      String jwkFilename = ns.getString("jwk_filename");
//      String jwk = new String(Files.readAllBytes(Paths.get(jwkFilename)));
//      String caUrl = ns.getString("ca_url");
//      String caFingerprint = ns.getString("ca_fingerprint");
//      String provisionerName = ns.getString("provisioner_name");
//      StepClient stepClient = new StepClient(caUrl, caFingerprint);
//
//
//      CSR csr = new CSR("example.com", List.of("example.com", "mysite.example.com"));
//      CAToken caToken = new CAToken(stepClient.getUrl(), stepClient.getFingerprint(), csr,
//        ns.toString(), jwk);
//      X509Certificate certificate = stepClient.sign(csr.toString(), caToken.toString());
//      byte[] certificatePemBytes = certificate.getEncoded();
//      byte[] certificateDerBytes = certificate.getEncoded();
//      PrivateKey privateKey = csr.getKey().getPrivate();
//      String encryptedPrivateKeyPem = csr.getKeyPem("mysecretpw");
//      System.out.println(new String(certificatePemBytes));
//    } catch (IOException | NoSuchAlgorithmException | OperatorCreationException e) {
//      e.printStackTrace();
//    } catch (CertificateEncodingException e) {
//      throw new RuntimeException(e);
//    }

        try {
            // Bootstraps with the SmallStep CA (localhost)
            String caUrl = "https://192.168.0.12";
            String caFingerprint = "0a8a45afaf1fa7287a7777630f2c3e10f09e0b138efab14c65e1dbaccdc37020";
            bootstrapWithCA(caUrl, caFingerprint);

            // Generates a new key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Creates a certificate request using the SmallStep CLI
            Process process = Runtime.getRuntime().exec(
                    "step ca certificate internal.example.com internal.crt internal.key --not-before " +
                            Date.from(Instant.now()).toString() + " --not-after " +
                            Date.from(Instant.now().plus(Duration.ofDays(30))).toString() +
                            " --key " + keyPair.getPrivate().getFormat());

            // Reads the output of the CLI command
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }

            // Parses the output to get the generated certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            System.out.println(reader.readLine());
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(output.toString().getBytes()));

            // Prints the generated certificate
            System.out.println(certificate);
        } catch (NoSuchAlgorithmException | IOException | CertificateException e) {
            e.printStackTrace();
        }
    }

    private static void bootstrapWithCA(String caUrl, String caFingerprint) throws IOException {
        // Downloads the CA root certificate
        Process process = Runtime.getRuntime().exec("step ca bootstrap --ca-url " + caUrl + " --fingerprint " + caFingerprint);

        // Reads the output of the CLI command
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line);
        }

        System.out.println("Downloaded CA root certificate: " + output);
    }
}

