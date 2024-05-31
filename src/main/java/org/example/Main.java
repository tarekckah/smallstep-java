package org.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.Namespace;

public class Main {
    public static void main(String[] args)
            throws Exception {
        ArgumentParser parser = ArgumentParsers.newFor("CSR Signing").build()
                .description("Get a CSR signed with a step-ca server.");
        parser.addArgument("ca_url").type(String.class).help("The step-ca URL");
        parser.addArgument("ca_fingerprint").type(String.class).help("The CA fingerprint");
        parser.addArgument("provisioner_name").type(String.class).help("The CA JWK provisioner to use");
        parser.addArgument("jwk_filename").type(String.class).help("The JWK private key filename (JSON formatted)");

        try {
            Namespace ns = parser.parseArgs(args);
            String jwkFilename = ns.getString("jwk_filename");
            String jwk = new String(Files.readAllBytes(Paths.get(jwkFilename)));
            String caUrl = ns.getString("ca_url");
            String caFingerprint = ns.getString("ca_fingerprint");
            String provisionerName = ns.getString("provisioner_name");
            StepClient stepClient = new StepClient(caUrl, caFingerprint);

            // Example uses
            CSR csr = new CSR("example.com", List.of("example.com", "mysite.example.com"));
            CAToken caToken = new CAToken(stepClient.getUrl(), stepClient.getFingerprint(), csr,
                    provisionerName, jwk);

            String csrPem = csr.toPem();
            String token = caToken.toString();

            X509Certificate certificate = stepClient.sign(csrPem, token);

            byte[] certificatePemBytes = certificate.getEncoded();
            byte[] certificateDerBytes = certificate.getEncoded();
            PrivateKey privateKey = csr.getKey().getPrivate();
            String encryptedPrivateKeyPem = csr.getKeyPem("mysecretpw");
            System.out.println(new String(certificatePemBytes));
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}