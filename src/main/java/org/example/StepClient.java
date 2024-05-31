package org.example;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import jakarta.xml.bind.DatatypeConverter;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.json.JSONObject;

public class StepClient {

  private String url;
  private String fingerprint;
  private String rootPem;
  private String certBundleFn;

  public StepClient(String caUrl, String caFingerprint) throws NoSuchAlgorithmException, KeyManagementException {
    this.url = caUrl;
    this.fingerprint = caFingerprint;
    this.rootPem = this.root();
    this.certBundleFn = this.saveTempFile(this.rootPem);
  }

  private String root() throws NoSuchAlgorithmException, KeyManagementException {
    // Disable TLS verification warnings for this request.
    System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
    System.setProperty("org.apache.commons.logging.simplelog.defaultlog", "error");

    PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                    .setSslContext(SSLContexts.createSystemDefault())
                    .setTlsVersions(TLS.V_1_3)
                    .build())
            .setDefaultSocketConfig(SocketConfig.custom()
                    .setSoTimeout(Timeout.ofMinutes(1))
                    .build())
            .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
            .setConnPoolPolicy(PoolReusePolicy.LIFO)
            .setDefaultConnectionConfig(ConnectionConfig.custom()
                    .setSocketTimeout(Timeout.ofMinutes(1))
                    .setConnectTimeout(Timeout.ofMinutes(1))
                    .setTimeToLive(TimeValue.ofMinutes(10))
                    .build())
            .build();

    try (CloseableHttpClient httpClient = HttpClientBuilder
            .create()
            .setConnectionManager(connectionManager)
            .build()) {
      HttpGet httpGet = new HttpGet(URI.create(url + "/root/" + fingerprint));
      CloseableHttpResponse response = httpClient.execute(httpGet);
      String responseBody = EntityUtils.toString(response.getEntity());
      JSONObject jsonObject = new JSONObject(responseBody);
      String rootPem = jsonObject.getString("ca");
      compareFingerprints(rootPem, fingerprint);
      return rootPem;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    } finally {
      // Re-enable TLS verification warnings
      System.setProperty("org.apache.commons.logging.simplelog.defaultlog", "info");
    }
  }

  //method that adds two numbers together








  public X509Certificate sign(String csr, String token) {
    try {
      // Create a trust manager that does not validate certificate chains
      TrustManager[] trustAllCerts = new TrustManager[]{
              new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                  return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
              }
      };

      // Install the all-trusting trust manager
      SSLContext sslContext = SSLContext.getInstance("SSL");
      sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

      PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
              .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                      .setSslContext(sslContext)
                      .setTlsVersions(TLS.V_1_3)
                      .build())
              .setDefaultSocketConfig(SocketConfig.custom()
                      .setSoTimeout(Timeout.ofMinutes(1))
                      .build())
              .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
              .setConnPoolPolicy(PoolReusePolicy.LIFO)
              .setDefaultConnectionConfig(ConnectionConfig.custom()
                      .setSocketTimeout(Timeout.ofMinutes(1))
                      .setConnectTimeout(Timeout.ofMinutes(1))
                      .setTimeToLive(TimeValue.ofMinutes(10))
                      .build())
              .build();

      CloseableHttpClient httpClient = HttpClientBuilder
              .create()
              .setConnectionManager(connectionManager)
              .build();

      HttpPost httpPost = new HttpPost(URI.create(url + "/1.0/sign"));
      JSONObject json = new JSONObject();
      json.put("csr", csr);
      json.put("ott", token);
      StringEntity entity = new StringEntity(json.toString());
      httpPost.setEntity(entity);
      httpPost.setHeader("Content-type", "application/json");

      HttpResponse response = httpClient.execute(httpPost);
      String responseBody = EntityUtils.toString(((CloseableHttpResponse) response).getEntity());
      JSONObject jsonObject = new JSONObject(responseBody);
      String crt = jsonObject.getString("crt");
      return loadPemX509Certificate(crt);
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  private X509Certificate loadPemX509Certificate(String pem) throws Exception {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream inputStream = new ByteArrayInputStream(pem.getBytes());
    return (X509Certificate) certificateFactory.generateCertificate(inputStream);
  }

  public void health() {
    try (CloseableHttpClient httpClient = HttpClients.custom().disableCookieManagement().build()) {
      HttpGet httpGet = new HttpGet(URI.create(url + "/health"));
      HttpResponse response = httpClient.execute(httpGet);
      String responseBody = EntityUtils.toString(((CloseableHttpResponse) response).getEntity());
      System.out.println(responseBody);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private String saveTempFile(String contents) {
    try {
      Path tempFilePath = Files.createTempFile(null, null);
      String fileName = tempFilePath.toAbsolutePath().toString();
      FileWriter fileWriter = new FileWriter(fileName);
      fileWriter.write(contents);
      fileWriter.close();
      Runtime.getRuntime().addShutdownHook(new Thread(() -> {
        try {
          Files.deleteIfExists(Paths.get(fileName));
        } catch (IOException e) {
          e.printStackTrace();
        }
      }));
      return fileName;
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    }
  }

  private void compareFingerprints(String pem, String fingerprint) throws NoSuchAlgorithmException, CertificateException {
    byte[] fingerprintBytes = DatatypeConverter.parseHexBinary(fingerprint);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pem.getBytes());
    X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
    byte[] certFingerprintBytes = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    if (!Arrays.equals(fingerprintBytes, certFingerprintBytes)) {
      throw new CertificateException("WARNING: fingerprints do not match");
    }
  }

  public String getUrl() {
    return url;
  }

  public String getFingerprint() {
    return fingerprint;
  }
}
