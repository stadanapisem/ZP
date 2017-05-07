package implementation;

import code.GuiException;

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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 *
 * @author Miljan
 */
public class MyCode extends x509.v3.CodeV3 {

    private KeyStore keyStore;
    private static String keyStorePath = "/home/mm/Desktop/keystore.jks";
    private static String keyStorePassword = "password";

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BC") == null) {
            throw new Error();
        }

        this.access.setVersion(2);
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
        createLocalKeystore(file);
    }

    @Override
    public int loadKeypair(String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                this.access.setNotAfter(cert.getNotAfter());
                this.access.setNotBefore(cert.getNotBefore());
                this.access.setSerialNumber(cert.getSerialNumber().toString());
                this.access.setVersion(2);
                this.access.setPublicKeySignatureAlgorithm(cert.getSigAlgName());

                Principal data = cert.getSubjectDN();
                this.access.setSubjectCountry(data.toString());

                return 1;
            }
            return 0;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
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

            // TODO Add the extra parameters
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
        //throw new UnsupportedOperationException("Not supported yet.");
        return true;
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean signCertificate(String string, String string1) {
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
    public String getIssuer(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getRSAKeyLength(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<String> getIssuers(String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                List<String> list = new ArrayList<>();
                list.add(cert.getIssuerDN().getName());
                return list;
            }
            
            return null;
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean generateCSR(String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                KeyPair pair = new KeyPair(cert.getPublicKey(), (PrivateKey) keyStore.getKey(alias, null));
                
                PKCS10CertificationRequest req = new PKCS10CertificationRequest(cert.getSigAlgName(), 
                        cert.getSubjectX500Principal(), pair.getPublic(), null, pair.getPrivate());
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
