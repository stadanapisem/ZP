package implementation;

import code.GuiException;
import java.io.ByteArrayOutputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import sun.security.x509.InhibitAnyPolicyExtension;

/**
 *
 * @author Miljan
 */
public class MyCode extends x509.v3.CodeV3 {

    private KeyStore keyStore;
    private static String keyStorePath = "/home/mm/Desktop/keystore.p12";
    private static String keyStorePassword = "password";
    private String aliasToSign;
    private PKCS10CertificationRequest req = null;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BC") == null) {
            throw new Error();
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {

        try {
            keyStore = KeyStore.getInstance("pkcs12");

            File file = new File(keyStorePath);

            if (file.exists() && file.isFile()) {
                FileInputStream in = new FileInputStream(file);
                keyStore.load(in, keyStorePassword.toCharArray());
                in.close();
            } else {
                createLocalKeystore(file);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                return keyStore.aliases();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return null;
    }

    private void createLocalKeystore(File file) {
        try {
            FileOutputStream out = new FileOutputStream(file);
            keyStore.load(null, keyStorePassword.toCharArray());
            keyStore.store(out, keyStorePassword.toCharArray());
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void resetLocalKeystore() {
        File file = new File(keyStorePath);
        file.delete();
        createLocalKeystore(file);
    }

    private boolean checkValidity(X509Certificate cert) {
        try {
            /*if(cert.getIssuerDN().toString().startsWith("CN=ETFrootCA")) {
                return true;
            }*/
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                Certificate c = keyStore.getCertificate(aliases.nextElement());
                try {
                    if (cert != c) {
                        cert.verify(c.getPublicKey());
                        return true;
                    }
                } catch (Exception e) {
//                    e.printStackTrace();
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean isSigned(X509Certificate cert) {
        try {
            if (cert.getKeyUsage() != null) {
                return cert.getKeyUsage()[5];
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public int loadKeypair(String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificateChain(alias)[0];
                this.access.setNotAfter(cert.getNotAfter());
                this.access.setNotBefore(cert.getNotBefore());
                this.access.setSerialNumber(cert.getSerialNumber().toString());
                this.access.setVersion(2);
                this.access.setSubjectSignatureAlgorithm(cert.getSigAlgName());

                Principal data = cert.getSubjectDN();
                String subjectArray[] = data.toString().split(",");
/// NEEDS COMPLETE REWORK
                if (subjectArray[0].length() > 3) {
                    this.access.setSubjectCommonName(subjectArray[0].trim().split("=")[1]);
                }
                if (subjectArray[1].length() > 4) {
                    this.access.setSubjectOrganizationUnit(subjectArray[1].trim().split("=")[1]);
                }
                if (subjectArray[2].length() > 3) {
                    this.access.setSubjectOrganization(subjectArray[2].trim().split("=")[1]);
                }
                if (subjectArray[3].length() > 3) {
                    this.access.setSubjectLocality(subjectArray[3].trim().split("=")[1]);
                }
                if (subjectArray[4].length() > 4) {
                    this.access.setSubjectState(subjectArray[4].trim().split("=")[1]);
                }
                if (subjectArray[5].length() > 3) {
                    this.access.setSubjectCountry(subjectArray[5].trim().split("=")[1]);
                }
/// THIS PART
                //  this.access.setSubjectCountry(data.toString());
                this.access.setIssuer(cert.getIssuerDN().toString());
                if (cert.getIssuerUniqueID() != null) {
                    this.access.setIssuerUniqueIdentifier(cert.getIssuerUniqueID().toString());
                }

                Set<String> critical = cert.getCriticalExtensionOIDs();

                // System.out.println(new String(cert.getExtensionValue("2.5.29.54")));
                if (cert.getExtensionValue("2.5.29.18") != null) {
                    byte[] tmp = cert.getExtensionValue("2.5.29.18");
                    this.access.setAlternativeName(6, new String(tmp, 6, tmp.length - 6)); // Surmised from precise measurements
                    this.access.setCritical(6, critical.contains("2.5.29.18"));
                }

                if (cert.getExtensionValue("2.5.29.54") != null) {
                    /*for(byte b : cert.getExtensionValue("2.5.29.54"))
                        System.out.println(b);*/
                    int tmp = cert.getExtensionValue("2.5.29.54")[4];
                    this.access.setSkipCerts(Integer.toString(tmp));
                    this.access.setCritical(13, critical.contains("2.5.29.54"));
                }

                if (cert.getExtensionValue("2.5.29.32") != null) {
                    //this.access.setAnyPolicy(true);
                    byte[] tmp = cert.getExtensionValue("2.5.29.32");
                    // 9 = 29 and 10 = 32 and 11 = 0 
                    // starting since 35
                    // magic constants ;D
                    if (tmp.length > 12) {
                        this.access.setCpsUri(new String(tmp, 35, tmp.length - 35));
                    } else if (tmp[9] == 29 && tmp[10] == 32 && tmp[11] == 0) {
                        this.access.setAnyPolicy(true);
                    }

                    this.access.setCritical(3, critical.contains("2.5.29.32"));
                }

                //System.out.println(cert.getIssuerX500Principal().toString());
                if (isSigned(cert)) {
                    return checkValidity(cert) == true ? 2 : 1;
                } else {
                    return 0;
                }
            }
            return -1;
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    private X509Certificate generateCertificate(KeyPair keys) {
        try {

            X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
            cert.setSerialNumber(new BigInteger(this.access.getSerialNumber()));
            cert.setSignatureAlgorithm(this.access.getPublicKeySignatureAlgorithm());
            X509Principal data = new X509Principal("C=" + this.access.getSubjectCountry() + ", ST=" + this.access.getSubjectState() + ", L=" + this.access.getSubjectLocality()
                    + ", O=" + this.access.getSubjectOrganization() + ", OU=" + this.access.getSubjectOrganizationUnit() + ", CN=" + this.access.getSubjectCommonName());

            cert.setSubjectDN(data);
            cert.setIssuerDN(new X509Principal("CN=localhost"));
            cert.setNotAfter(this.access.getNotAfter());
            cert.setNotBefore(this.access.getNotBefore());
            cert.setPublicKey(keys.getPublic());

//            cert.addExtension(X509Extensions.IssuerAlternativeName, this.access.isCritical(1), Arrays.toString(this.access.getAlternativeName(2)).getBytes());
            //ExtensionsGenerator gen = new ExtensionsGenerator();
            //gen.addExtension(X509Extensions.IssuerAlternativeName, this.access.isCritical(1), new IssuerAlternativeNameExtension(this.access.getAlternativeName(0)));
            //cert.addExtension(X509Extensions.CertificatePolicies, this.access.isCritical(0), new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(this.access.getCpsUri()))));
            //cert.addExtension(X509Extensions.InhibitAnyPolicy, this.access.isCritical(2), "".getBytes());
            GeneralNamesBuilder gnbuilder = new GeneralNamesBuilder();

            for (String s : this.access.getAlternativeName(6)) { // For some reason it returns something only on 6
                String[] tmp = s.trim().split(":");
                switch (tmp[0]) {
                    case "DNS":
                        gnbuilder.addName(new GeneralName(GeneralName.dNSName, tmp[1]));
                        break;
                    case "email":
                        gnbuilder.addName(new GeneralName(GeneralName.rfc822Name, tmp[1]));
                        break;
                    case "URI":
                        gnbuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, tmp[1]));
                        break;
                    case "IP":
                        gnbuilder.addName(new GeneralName(GeneralName.iPAddress, tmp[1]));
                        break;
                    case "RID":
                        gnbuilder.addName(new GeneralName(GeneralName.registeredID, tmp[1]));
                        break;
                    case "DIR":
                        gnbuilder.addName(new GeneralName(GeneralName.directoryName, tmp[1]));
                        break;
                    default:
                        gnbuilder.addName(new GeneralName(GeneralName.otherName, tmp[1]));
                }
            }

            /*for(int i = 0; i < 15; i++)     //   3 = Certificate policies; 6 = Issuer Alternative Name 13 = Inhibit any Policy; The joy of no documentation :D
                System.out.println(this.access.isCritical(i));*/
            GeneralNames names = gnbuilder.build();
            if (this.access.getAlternativeName(6).length > 0) {
                cert.addExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName, this.access.isCritical(6), names.getEncoded());
            }

            if (!this.access.getSkipCerts().equals("")) {
                cert.addExtension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy, this.access.isCritical(13), // Should always be true in inhibit any policy
                        new DERInteger(new BigInteger(this.access.getSkipCerts())).getEncoded());
            }

            if (this.access.getAnyPolicy()) {
                PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.26"), new DERSequence(new PolicyQualifierInfo(this.access.getCpsUri())));
                cert.addExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies, this.access.isCritical(3), new CertificatePolicies(pi).getEncoded());
            } else {
                cert.addExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies, this.access.isCritical(3), new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32.0"))).getEncoded());
            }

            return cert.generate(keys.getPrivate(), "BC");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        /*try {
            X500NameBuilder nameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());
            nameBuilder.addRDN(BCStyle.C, this.access.getSubjectCountry());
            nameBuilder.addRDN(BCStyle.CN, this.access.getSubjectCommonName());
            nameBuilder.addRDN(BCStyle.OU, this.access.getSubjectOrganizationUnit());
            nameBuilder.addRDN(BCStyle.O, this.access.getSubjectOrganization());
            nameBuilder.addRDN(BCStyle.L, this.access.getSubjectLocality());
            nameBuilder.addRDN(BCStyle.ST, this.access.getSubjectState());

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(nameBuilder.build(),
                    new BigInteger(this.access.getSerialNumber()), this.access.getNotBefore(), this.access.getNotAfter(),
                    nameBuilder.build(), SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keys.getPublic().getEncoded())));

            System.out.println(this.access.getSkipCerts());
            if (!this.access.getSkipCerts().equals("")) {
                certBuilder.addExtension(new org.bouncycastle.asn1.x509.Extension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy, this.access.isCritical(13),
                        new DERInteger(new BigInteger(this.access.getSkipCerts())).getEncoded()));
            }
            System.out.println(this.access.getAnyPolicy());
            
            //PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.26")); // onaj string 
            PolicyInformation[] pi = new PolicyInformation[1];
            PolicyQualifierInfo piq = new PolicyQualifierInfo(this.access.getCpsUri());
            //pi[0] = new PolicyInformation(new ASN1ObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.26"), new DERSequence(new PolicyQualifierInfo(this.access.getCpsUri())));
            
            certBuilder.addExtension(new org.bouncycastle.asn1.x509.Extension(org.bouncycastle.asn1.x509.Extension.certificatePolicies, this.access.isCritical(3),
                    new CertificatePolicies(pi).getEncoded()));

            //X509CertificateHolder certHolder = certBuilder.build(null)
            System.out.println(this.access.getPublicKeySignatureAlgorithm());
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(new JcaContentSignerBuilder(this.access.getPublicKeySignatureAlgorithm()).setProvider("BC")
                    .build(keys.getPrivate())));
        } catch (Exception e) {
            e.printStackTrace();
        }
         */
    }

    @Override
    public boolean saveKeypair(String name) {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(this.access.getPublicKeyECCurve());
            KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", "BC");
            gen.initialize(ecSpec, new SecureRandom());
            KeyPair keys = gen.generateKeyPair();
            System.out.println(this.access.getPublicKeySignatureAlgorithm());
            System.out.println(keys.getPrivate().toString());
            Certificate[] cert = new Certificate[1];
            cert[0] = generateCertificate(keys);
            keyStore.setKeyEntry(name, keys.getPrivate(), null, cert);
            keyStore.store(new FileOutputStream(new File(keyStorePath)), keyStorePassword.toCharArray());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean removeKeypair(String alias) {
        try {
            keyStore.deleteEntry(alias);
            keyStore.store(new FileOutputStream(new File(keyStorePath)), keyStorePassword.toCharArray());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean importKeypair(String name, String path, String password) {
        try {
            KeyStore p12 = KeyStore.getInstance("pkcs12");
            p12.load(new FileInputStream(path), password.toCharArray());
            Enumeration e = p12.aliases();
            while (e.hasMoreElements()) {
                String alias = (String) e.nextElement();
                X509Certificate c = (X509Certificate) p12.getCertificate(alias);
                Principal subject = c.getSubjectDN();
                String subjectArray[] = subject.toString().split(",");
                for (String s : subjectArray) {
                    String[] str = s.trim().split("=");
                    System.out.println(str[0] + " - " + str[1]);
                }
                Certificate[] cert = new Certificate[1];
                cert[0] = c;
                keyStore.setKeyEntry(alias, p12.getKey(alias, password.toCharArray()), null, cert);
                keyStore.store(new FileOutputStream(new File(keyStorePath)), keyStorePassword.toCharArray());
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean exportKeypair(String alias, String path, String password) {
        try {
            KeyStore p12 = KeyStore.getInstance("pkcs12");
            FileOutputStream out = new FileOutputStream(path + ".p12");
            p12.load(null, password.toCharArray());
            p12.setEntry(alias, keyStore.getEntry(alias, new KeyStore.PasswordProtection(null)), new KeyStore.PasswordProtection(password.toCharArray()));
            p12.store(out, password.toCharArray());

            out.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean signCertificate(String name, String algorithm) {
        try {
            if (keyStore.containsAlias(name) && keyStore.containsAlias(aliasToSign)) {
                //System.out.println(req.getSignature());
                PrivateKey pkey = (PrivateKey) keyStore.getKey(name, null);

                X509Certificate cert = (X509Certificate) keyStore.getCertificateChain(name)[0];
                AlgorithmIdentifier sigAlg = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
                AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);
                X500Name issuer = new X500Name(cert.getSubjectX500Principal().getName());
                BigInteger serial = new BigInteger(32, new SecureRandom());
                X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, cert.getNotBefore(),
                        cert.getNotAfter(), req.getSubject(), req.getSubjectPublicKeyInfo());

                ContentSigner signer = new BcRSAContentSignerBuilder(digAlg, digAlg).build(PrivateKeyFactory.createKey(pkey.getEncoded()));

                X509CertificateHolder certHolder = certgen.build(signer);
//                keyStore.deleteEntry(aliasToSign);
                keyStore.setCertificateEntry(aliasToSign, new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder));
                /*byte[] certEncode = certHolder.toASN1Structure().getEncoded();

                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                signer = new JcaContentSignerBuilder(algorithm).build(pkey);
                generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, cert));
                generator.addCertificate(new X509CertificateHolder(certEncode));
                generator.addCertificate(new X509CertificateHolder(cert.getEncoded()));

                CMSTypedData content = new CMSProcessableByteArray(certEncode);
                CMSSignedData signeddata = generator.generate(content, true);

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write("-----BEGIN PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
                out.write(Base64.encode(signeddata.getEncoded()));
                out.write("\n-----END PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
                out.close();
                System.out.println(new String(out.toByteArray(), "ISO-8859-1"));*/
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean importCertificate(File file, String name) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getIssuer(String name) {
        try {
            if (keyStore.containsAlias(name)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificateChain(name)[0];
                return cert.getIssuerX500Principal().getName();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String issuer) {
        try {
            if (keyStore.containsAlias(issuer)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificateChain(issuer)[0];
                return keyStore.getKey(issuer, null).getAlgorithm();
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return null;
    }

    @Override
    public int getRSAKeyLength(String issuer) {
        try {
            if (keyStore.containsAlias(issuer)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificateChain(issuer)[0];
                return cert.getSignature().length;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }

        return -1;
    }

    @Override
    public List<String> getIssuers(String alias) { // TODO get ones which can sign a certificate
        try {
            Enumeration e = keyStore.aliases();
            List<String> list = new ArrayList<>();

            while (e.hasMoreElements()) {
                String tmp = (String) e.nextElement();
                if (!alias.equals(tmp)) {
                    list.add(tmp);
                }
            }

            return list;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean generateCSR(String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                aliasToSign = alias;
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                KeyPair pair = new KeyPair(cert.getPublicKey(), (PrivateKey) keyStore.getKey(alias, null));
                PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(cert.getSubjectX500Principal(), pair.getPublic());
                JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(cert.getSigAlgName());
                ContentSigner signer = signerBuilder.build(pair.getPrivate());
                req = builder.build(signer);
                /*req = new PKCS10CertificationRequest(cert.getSigAlgName(),
                        cert.getSubjectX500Principal(), pair.getPublic(), null, pair.getPrivate());*/
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
