package implementation;

import code.GuiException;
import java.io.File;
import java.util.Enumeration;
import java.util.List;

/**
 *
 * @author mm
 */
public class MyCode extends x509.v3.CodeV3 {

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int loadKeypair(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean saveKeypair(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeKeypair(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean signCertificate(String string, String string1) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean importCertificate(File file, String string) {
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
    public List<String> getIssuers(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean generateCSR(String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
