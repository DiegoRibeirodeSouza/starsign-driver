import java.security.*;
import java.util.*;

public class test_java {
    public static void main(String[] args) throws Exception {
        String config = "--name=OpenSC\nlibrary=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n";
        Provider p = java.security.Security.getProvider("SunPKCS11");
        p = p.configure(config);
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, "<SEU_PIN_AQUI>".toCharArray());
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
            Key key = ks.getKey(alias, null);
            System.out.println("Key class: " + key.getClass().getName());
            if (key instanceof java.security.interfaces.RSAPrivateKey) {
                System.out.println("Is RSAPrivateKey");
            } else {
                System.out.println("NOT RSAPrivateKey!");
            }
        }
    }
}
