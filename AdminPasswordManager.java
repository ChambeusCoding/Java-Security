import java.io.*;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class AdminPasswordManager {

    private static final String ADMIN_PASSWORD_FILE = "admin_password.txt";
    private static final String ENCRYPTION_KEY = "0123456789abcdef";  // 16-byte key for AES

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter admin password: ");
        String enteredAdminPassword = scanner.nextLine();

        // Attempt to verify the admin password
        if (verifyAdminPassword(enteredAdminPassword)) {
            System.out.println("Admin access granted.");
            resetUserPassword();
        } else {
            System.out.println("Incorrect admin password.");
        }
    }

    public static void storeAdminPassword(String password) {
        try {
            String encryptedPassword = encryptPassword(password);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(ADMIN_PASSWORD_FILE))) {
                writer.write(encryptedPassword);
            }
        } catch (Exception e) {
            System.err.println("Error storing admin password: " + e.getMessage());
        }
    }

    public static boolean verifyAdminPassword(String enteredPassword) {
        try {
            // Read the encrypted password from the file
            String storedEncryptedPassword = readAdminPassword();
            // Decrypt the password read from the file
            String decryptedPassword = decryptPassword(storedEncryptedPassword);
            // Compare the decrypted password to the entered one
            return decryptedPassword.equals(enteredPassword);
        } catch (Exception e) {
            System.err.println("Error verifying admin password: " + e.getMessage());
            return false;
        }
    }

    public static String readAdminPassword() throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(ADMIN_PASSWORD_FILE))) {
            return reader.readLine();
        }
    }

    public static void resetUserPassword() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter new user password: ");
        String newPassword = scanner.nextLine();
        PasswordManager2.storeAdminPassword(newPassword);  // Reuse the storePassword method from PasswordManager class
        System.out.println("User password has been reset.");
    }

    // AES Encryption (ECB Mode)
    public static String encryptPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // AES Decryption
    public static String decryptPassword(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }
}