import java.security.*;
import java.util.*;

public class test_java4 {
    public static void main(String[] args) throws Exception {
        String config = "--name=OpenSC\nlibrary=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n";
        Provider p = java.security.Security.getProvider("SunPKCS11");
        p = p.configure(config);
        Security.addProvider(p);
        
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, "<SEU_PIN_AQUI>".toCharArray());
        Enumeration<String> aliases = ks.aliases();
        if (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Using Alias: " + alias);
            PrivateKey key = (PrivateKey) ks.getKey(alias, null);
            
            System.out.println("Testing NONEwithRSA:");
            try {
                Signature sig = Signature.getInstance("NONEwithRSA", p);
                sig.initSign(key);
                System.out.println("Init successful!");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
