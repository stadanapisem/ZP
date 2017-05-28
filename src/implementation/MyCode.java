package implementation;

import code.GuiException;
import java.io.BufferedInputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

/**
 *
 * @author Miljan
 */
public class MyCode extends x509.v3.CodeV3 {

    private KeyStore keyStore;
    private static String keyStorePath = "/home/mm/Desktop/keystore.p12";
    private static String keyStorePassword = "password";
    private String aliasToSign, aliasToExport;
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

    private void saveKeystore() {

        File file = new File(keyStorePath);
        try (FileOutputStream out = new FileOutputStream(file)) {
            keyStore.store(out, keyStorePassword.toCharArray());
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void resetLocalKeystore() {
        File file = new File(keyStorePath);
        file.delete();
        loadLocalKeystore();
    }

    private boolean checkValidity(Certificate[] certs) {
        try {
            List<X509Certificate> list = new ArrayList();
            for (int i = 0; i < certs.length; i++) {
                list.add((X509Certificate) certs[i]);
            }

            Enumeration e = keyStore.aliases();
            boolean path_found = false;
            
            while (e.hasMoreElements()) {
                String alias = (String) e.nextElement();
                X509Certificate c = (X509Certificate) keyStore.getCertificate(alias);

                if (c.getBasicConstraints() != -1) { // This one is CA
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    CertPath cp = cf.generateCertPath(Arrays.asList(list.get(0)));
                    TrustAnchor trust = new TrustAnchor(c, null);
                    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                    PKIXParameters params = new PKIXParameters(Collections.singleton(trust));
                    params.setRevocationEnabled(false);

                    try {
                        cpv.validate(cp, params);
                        path_found = true;
                        break;
                    } catch (Exception exc) {
                        exc.printStackTrace();
                        continue;
                    }
                }

            }
            return path_found;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean isSigned(Certificate[] certs) {
        try {
            X509Certificate cert = (X509Certificate) certs[0];

            if (cert.getBasicConstraints() != -1) {
                return true;
            }

            PublicKey key = cert.getPublicKey();
            cert.verify(key);

            return false;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }

    @Override
    public int loadKeypair(String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                aliasToExport = alias;
                X509Certificate cert = null;

                if (keyStore.isCertificateEntry(alias)) {
                    cert = (X509Certificate) keyStore.getCertificate(alias);
                } else {
                    cert = (X509Certificate) keyStore.getCertificateChain(alias)[0];
                }

                //System.out.println(cert.getSigAlgName());
                //System.out.println(new DefaultAlgorithmNameFinder().getAlgorithmName(new ASN1ObjectIdentifier(cert.getSigAlgOID())));
                this.access.setNotAfter(cert.getNotAfter());
                this.access.setNotBefore(cert.getNotBefore());
                this.access.setSerialNumber(cert.getSerialNumber().toString());
                this.access.setVersion(2);
                this.access.setSubjectSignatureAlgorithm(new DefaultAlgorithmNameFinder().getAlgorithmName(new ASN1ObjectIdentifier(cert.getSigAlgOID())));

                X500Principal data = cert.getSubjectX500Principal();

                String subjectArray[] = data.toString().split(",");
                //System.out.println(name.getName());
                for (String tmp : subjectArray) {
                    String[] attribute = tmp.trim().split("=");
                    if (attribute.length == 2) {
                        switch (attribute[0]) {
                            case "CN":
                                this.access.setSubjectCommonName(attribute[1]);
                                break;

                            case "OU":
                                this.access.setSubjectOrganizationUnit(attribute[1]);
                                break;

                            case "O":
                                this.access.setSubjectOrganization(attribute[1]);
                                break;

                            case "L":
                                this.access.setSubjectLocality(attribute[1]);
                                break;

                            case "ST":
                                this.access.setSubjectState(attribute[1]);
                                break;

                            case "C":
                                this.access.setSubjectCountry(attribute[1]);
                                break;

                        }
                    }
                }

                //  this.access.setSubjectCountry(data.toString());
                this.access.setIssuer(cert.getIssuerDN().toString());

                if (cert.getIssuerUniqueID() != null) {
                    this.access.setIssuerUniqueIdentifier(cert.getIssuerUniqueID().toString());
                }

                Set<String> critical = cert.getCriticalExtensionOIDs();

                // System.out.println(new String(cert.getExtensionValue("2.5.29.54")));
                if (cert.getExtensionValue("2.5.29.18") != null) { // Subject Alternative Names
                    byte[] tmp = cert.getExtensionValue("2.5.29.18");
                    this.access.setAlternativeName(6, new String(tmp, 6, tmp.length - 6)); // Surmised from precise measurements
                    this.access.setCritical(6, critical.contains("2.5.29.18"));
                }

                if (cert.getExtensionValue("2.5.29.54") != null) { // Inhibit Any Policy
                    /*for(byte b : cert.getExtensionValue("2.5.29.54"))
                        System.out.println(b);*/
                    int tmp = cert.getExtensionValue("2.5.29.54")[4];
                    this.access.setSkipCerts(Integer.toString(tmp));
                    this.access.setCritical(13, critical.contains("2.5.29.54"));
                }

                if (cert.getExtensionValue("2.5.29.32") != null) { // Certificate Policies
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
                if (keyStore.isCertificateEntry(alias)) { // Always trust imported certificate. User knows what he's doing.
                    return 2;
                } else {
                    if (isSigned(keyStore.getCertificateChain(alias))) {
                        return checkValidity(keyStore.getCertificateChain(alias)) == true ? 2 : 1;
                    } else {
                        return 0;
                    }
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

            /*for(int i = 0; i < 15; i++)     //   3 = Certificate policies; 6 = Issuer Alternative Name 13 = Inhibit any Policy; The joys of no documentation :D
                System.out.println(this.access.isCritical(i));*/
            GeneralNames names = gnbuilder.build();
            if (this.access.getAlternativeName(6).length > 0) { // Can't be critical, errors if it is
                cert.addExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName, false, names.getEncoded());
            }

            if (!this.access.getSkipCerts().equals("")) {
                cert.addExtension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy, true, // Should always be critical in inhibit any policy
                        new DERInteger(new BigInteger(this.access.getSkipCerts())).getEncoded()); // DERInteger... Who would have tought?
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
    }

    @Override
    public boolean saveKeypair(String name) {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(this.access.getPublicKeyECCurve());
            KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", "BC");
            gen.initialize(ecSpec, new SecureRandom());
            KeyPair keys = gen.generateKeyPair();

            //System.out.println(this.access.getPublicKeySignatureAlgorithm());
            //System.out.println(keys.getPrivate().toString());
            Certificate[] cert = new Certificate[1];
            cert[0] = generateCertificate(keys);
            keyStore.setKeyEntry(name, keys.getPrivate(), null, cert);
            saveKeystore();
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
            saveKeystore();
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
                    // System.out.println(str[0] + " - " + str[1]);
                }

                Certificate[] cert = new Certificate[1];
                cert[0] = c;
                keyStore.setKeyEntry(alias, p12.getKey(alias, password.toCharArray()), null, cert);
                saveKeystore();
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

            out.flush();
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
                X509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) keyStore.getCertificate(name));
                X509Certificate toSign = (X509Certificate) keyStore.getCertificateChain(aliasToSign)[0];
                X500Name issuer = certHolder.getSubject();
                X500Name subject = req.getSubject();

                X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, toSign.getSerialNumber(), toSign.getNotBefore(),
                        toSign.getNotAfter(), subject, req.getSubjectPublicKeyInfo());

                org.bouncycastle.asn1.pkcs.Attribute[] extAtributes = req.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

                if (extAtributes != null) {
                    Extensions extensions = Extensions.getInstance(extAtributes[0].getAttrValues().getObjectAt(0));
                    Enumeration oids = extensions.oids();

                    while (oids.hasMoreElements()) {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) oids.nextElement();
                        certBuilder.addExtension(oid, extensions.getExtension(oid).isCritical(), extensions.getExtension(oid).getParsedValue());
                    }
                }

                AlgorithmIdentifier signAlg = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
                AlgorithmIdentifier digestAlg = new DefaultDigestAlgorithmIdentifierFinder().find(signAlg);

                ContentSigner signer = new BcRSAContentSignerBuilder(signAlg, digestAlg).build(PrivateKeyFactory.createKey(pkey.getEncoded()));
                X509CertificateHolder signedCertHolder = certBuilder.build(signer);

                X509Certificate signedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(signedCertHolder);

                pkey = (PrivateKey) keyStore.getKey(aliasToSign, null);
                keyStore.deleteEntry(aliasToSign);

                Certificate[] cert = new Certificate[1];
                cert[0] = signedCert;

                keyStore.setKeyEntry(aliasToSign, pkey, null, cert);
                saveKeystore();

                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean importCertificate(File file, String name) {
        try {

            try (BufferedInputStream buff = new BufferedInputStream(new FileInputStream(file))) {
                CertificateFactory certf = CertificateFactory.getInstance("X.509");
                if (buff.available() > 0) {
                    Certificate cert = certf.generateCertificate(buff);
                    keyStore.setCertificateEntry(name, cert);
                    saveKeystore();
                }
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        try (FileOutputStream out = new FileOutputStream(file)) {

            Certificate cert = keyStore.getCertificateChain(aliasToExport)[0];
            if (i == 0) {  // export to DER
                out.write(cert.getEncoded());
            } else { // pem
                out.write("-----BEGIN CERTIFICATE-----".getBytes());
                out.write(java.util.Base64.getEncoder().withoutPadding().encode(cert.getEncoded()));
                out.write("-----END CERTIFICATE-----".getBytes());
            }

            out.flush();
            out.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
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
                    X509Certificate cert = null;
                    if (keyStore.getCertificateChain(tmp) != null) {
                        cert = (X509Certificate) keyStore.getCertificateChain(tmp)[0];
                    }
                    //System.out.println(cert.getBasicConstraints());
                    if (cert != null && cert.getBasicConstraints() != -1) {
                        list.add(tmp);
                    }
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

                ExtensionsGenerator extensions = new ExtensionsGenerator();

                Set<String> critical = cert.getCriticalExtensionOIDs();
                for (String tmp : critical) {
                    byte[] data = cert.getExtensionValue(tmp);
                    extensions.addExtension(new org.bouncycastle.asn1.x509.Extension(new ASN1ObjectIdentifier(tmp), true, Arrays.copyOfRange(data, 2, data.length)));
                }

                Set<String> noncritical = cert.getNonCriticalExtensionOIDs();
                for (String tmp : noncritical) {
                    byte[] data = cert.getExtensionValue(tmp);
                    extensions.addExtension(new org.bouncycastle.asn1.x509.Extension(new ASN1ObjectIdentifier(tmp), false, Arrays.copyOfRange(data, 2, data.length)));
                }

                PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(cert.getSubjectX500Principal(), pair.getPublic());

                if (!extensions.isEmpty()) {
                    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
                }
                //System.out.println(cert.getSigAlgName());
                req = builder.build(new JcaContentSignerBuilder(new DefaultAlgorithmNameFinder().getAlgorithmName(new ASN1ObjectIdentifier(cert.getSigAlgOID()))).build(pair.getPrivate()));

                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
