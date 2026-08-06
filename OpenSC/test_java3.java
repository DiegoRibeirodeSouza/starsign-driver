import java.security.*;
import java.util.*;

public class test_java3 {
    public static void main(String[] args) throws Exception {
        String config = "--name=OpenSC\nlibrary=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n";
        Provider p = java.security.Security.getProvider("SunPKCS11");
        p = p.configure(config);
        System.out.println("Algorithms in SunPKCS11-OpenSC:");
        for (Provider.Service s : p.getServices()) {
            if (s.getType().equals("Signature")) {
                System.out.println(s.getAlgorithm());
            }
        }
    }
}
