import java.security.*;
import java.util.*;

public class test_java2 {
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
            
            System.out.println("Interfaces implemented by key class:");
            for (Class<?> c : key.getClass().getInterfaces()) {
                System.out.println(" - " + c.getName());
            }
            Class<?> sc = key.getClass().getSuperclass();
            while (sc != null) {
                System.out.println("Superclass: " + sc.getName());
                for (Class<?> c : sc.getInterfaces()) {
                    System.out.println(" - " + c.getName());
                }
                sc = sc.getSuperclass();
            }
        }
    }
}
