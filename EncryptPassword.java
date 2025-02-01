import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class EncryptPassword {

    private static final String ENCRYPTION_KEY = "0123456789abcdef"; // 16-byte key for AES

    public static void main(String[] args) {
        try {
            String password = "PointBreak47!x";
            String encryptedPassword = encryptPassword(password);
            System.out.println("Encrypted password (Base64 encoded): " + encryptedPassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // AES Encryption
    public static String encryptPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
