package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class CAToken {
  private String caUrl;
  private String caFingerprint;
  private String provisionerName;
  private CSR csr;
  private String token;

  public CAToken(String caUrl, String caFingerprint, CSR csr,
                 String provisionerName, String jwk)
          throws Exception {
    this.caUrl = caUrl;
    this.caFingerprint = caFingerprint;
    this.csr = csr;
    this.provisionerName = provisionerName;

    // Add BouncyCastleProvider
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    PrivateKey privateKey = loadPrivateKey("/Users/tarekchahin/.step/secrets/root_ca_key", "1234");

    // Create JWT
    this.token = Jwts.builder()
            .setAudience(this.caUrl + "/1.0/sign")
            .claim("sha", this.caFingerprint)
            .setExpiration(Date.from(Instant.now().plus(5000, ChronoUnit.MINUTES)))
            .setIssuedAt(Date.from(Instant.now()))
            .setNotBefore(Date.from(Instant.now()))
            .setId(UUID.randomUUID().toString())
            .setIssuer(this.provisionerName)
            .claim("sans", csr.getDnsSans())
            .setSubject(csr.getCn())
            .signWith(privateKey, SignatureAlgorithm.ES256)
            .compact();
  }

  private PrivateKey loadPrivateKey(String privateKeyPath, String password) throws IOException, Exception {
    try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath))) {
      Object object = pemParser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      if (object instanceof PEMEncryptedKeyPair) {
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
        return converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv)).getPrivate();
      } else if (object instanceof PEMKeyPair) {
        return converter.getKeyPair((PEMKeyPair) object).getPrivate();
      } else {
        throw new IllegalArgumentException("Invalid key format");
      }
    }
  }

  public String getToken() {
    return token;
  }

  @Override
  public String toString() {
    return this.token;
  }
}
