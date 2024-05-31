package org.example;

import java.io.IOException;
import java.io.StringWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class PemUtils {

    // Convert a PKCS10CertificationRequest to a PEM formatted string
    public static String encodeToPem(PKCS10CertificationRequest csr) throws IOException {
        return encodeObjectToPem("CERTIFICATE REQUEST", csr.getEncoded());
    }

    // General method to convert any object to PEM format
    private static String encodeObjectToPem(String type, byte[] encoded) throws IOException {
        PemObject pemObject = new PemObject(type, encoded);
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(pemObject);
        }
        return stringWriter.toString();
    }
}