package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

public class CAToken {
  private String caUrl;
  private String caFingerprint;
  private String provisionerName;
  private CSR csr;
  private String token;

  public CAToken(String caUrl, String caFingerprint, CSR csr,
                 String provisionerName, String jwk) {
    this.caUrl = caUrl;
    this.caFingerprint = caFingerprint;
    this.csr = csr;
    this.provisionerName = provisionerName;

    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    // Creates a JWT
    this.token = Jwts.builder()
      .setAudience(this.caUrl + "/1.0/sign")
      .claim("sha", this.caFingerprint)
      .setExpiration(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
      .setIssuedAt(Date.from(Instant.now()))
      .setNotBefore(Date.from(Instant.now()))
      .setId(UUID.randomUUID().toString())
      .setIssuer(this.provisionerName)
      .claim("sans", csr.getDnsSans())
      .setSubject(csr.getCn())
      .signWith(Keys.hmacShaKeyFor(jwk.getBytes()), SignatureAlgorithm.ES256)
      .compact();
  }

  public String getToken() {
    return token;
  }
}
