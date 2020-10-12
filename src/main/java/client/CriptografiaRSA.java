package client;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class CriptografiaRSA {

    public static final String ALGORITHM = "RSA";

    public static byte[] criptografar(String texto, PublicKey chave) {
        byte[] cipherText = null;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, chave);

            cipherText = cipher.doFinal(texto.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return cipherText;
    }

}
