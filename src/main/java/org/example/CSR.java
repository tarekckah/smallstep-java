package org.example;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

public class CSR {

  private KeyPair key;
  private String cn;
  private List<String> dnsSans;
  private byte[] csrPemBytes;

  public CSR(String cn, List<String> dnsSans)
    throws NoSuchAlgorithmException, OperatorCreationException, IOException, InvalidAlgorithmParameterException {
    Security.addProvider(new BouncyCastleProvider());
    this.key = generatePrivateKey();
    this.cn = cn;
    this.dnsSans = dnsSans;
    this.csrPemBytes = generateCSR();
  }

  private KeyPair generatePrivateKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(new ECGenParameterSpec("secp384r1"));
    return keyGen.generateKeyPair();
  }

  private byte[] generateCSR()
    throws OperatorCreationException, IOException {
    X500Name subject = new X500Name("CN=" + cn);
    ExtensionsGenerator extGen = new ExtensionsGenerator();

    List<GeneralName> sans = dnsSans.stream().map(name -> new GeneralName(GeneralName.dNSName, new DERIA5String(name))).toList();
    GeneralNames subjectAltName = new GeneralNames(sans.toArray(new GeneralName[0]));

    extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
    extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    extGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));

    Extensions extensions = extGen.generate();

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate());

    PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, key.getPublic())
      .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions)
      .build(signer);

    return csr.getEncoded();
  }

  public byte[] getCSR() {
    return csrPemBytes;
  }

  public String getCn() { return cn; }

  public String getKeyPem(String passphrase) throws IOException {
    ByteArrayOutputStream keyPemStream = new ByteArrayOutputStream();
    JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(keyPemStream));
    pemWriter.writeObject(key, new JcePEMEncryptorBuilder("AES-256-CBC").build(passphrase.toCharArray()));
    pemWriter.close();
    return keyPemStream.toString();
  }

  public List<String> getDnsSans() {
    return dnsSans;
  }

  public KeyPair getKey() {
    return key;
  }
}
