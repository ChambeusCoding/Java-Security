import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager2 {

    // Constants for file names and encryption key
    private static final String USER_PASSWORD_FILE = "user_password.txt";
    private static final String ADMIN_PASSWORD_FILE = "admin_password.txt";
    private static final String ENCRYPTION_KEY = "0123456789abcdef";  // 16-byte key for AES

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. User Mode\n2. Admin Mode\nChoose your option: ");
        int choice = scanner.nextInt();
        scanner.nextLine();  // consume the newline character

        if (choice == 1) {
            // User mode: Generate or verify user password
            handleUserPassword();
        } else if (choice == 2) {
            // Admin mode: Verify admin password and reset user password
            handleAdminPassword(scanner);
        } else {
            System.out.println("Invalid option. Exiting...");
        }
    }

    // Handle user password generation and verification
    public static void handleUserPassword() {
        File passwordFile = new File(USER_PASSWORD_FILE);

        if (!passwordFile.exists()) {
            // First run: Generate and store a new user password
            String generatedPassword = generatePassword();
            System.out.println("Your user password is: " + generatedPassword);
            storeUserPassword(generatedPassword);
        } else {
            // Subsequent runs: Verify user password
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter your password: ");
            String enteredPassword = scanner.nextLine();
            if (verifyUserPassword(enteredPassword)) {
                System.out.println("Access granted.");
            } else {
                System.out.println("Incorrect password. Access denied.");
            }
        }
    }

    // Handle admin password verification and user password reset
    public static void handleAdminPassword(Scanner scanner) {
        File adminPasswordFile = new File(ADMIN_PASSWORD_FILE);

        // If no admin password exists, create one
        if (!adminPasswordFile.exists()) {
            System.out.print("Enter admin password to set: ");
            String adminPassword = scanner.nextLine();
            storeAdminPassword(adminPassword); // Store the encrypted admin password
            System.out.println("Admin password set successfully.");
        }

        // Prompt for admin password
        System.out.print("Enter admin password: ");
        String enteredAdminPassword = scanner.nextLine();

        if (verifyAdminPassword(enteredAdminPassword)) {
            System.out.println("Admin access granted... Accessing W.O.P.R");
            System.out.println("Greetings Professor Falken... Shall we play a game?");
            resetUserPassword(scanner);
        } else {
            System.out.println("Incorrect admin password.");
        }
    }

    // Generate a random password of 12 characters
    public static String generatePassword() {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

        for (int i = 0; i < 12; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }

        return password.toString();
    }

    // Encrypt the user password using AES
    public static String encryptUserPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Store the user password to the file with encryption
    public static void storeUserPassword(String password) {
        try {
            String encryptedPassword = encryptUserPassword(password);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(USER_PASSWORD_FILE))) {
                writer.write(encryptedPassword);
            }
        } catch (Exception e) {
            System.err.println("Error storing user password: " + e.getMessage());
        }
    }

    // Decrypt the user password using AES
    public static String decryptUserPassword(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }

    // Verify the user password by comparing the decrypted stored password
    public static boolean verifyUserPassword(String enteredPassword) {
        try {
            String storedEncryptedPassword = readUserPassword();
            String decryptedPassword = decryptUserPassword(storedEncryptedPassword);
            return decryptedPassword.equals(enteredPassword);
        } catch (Exception e) {
            System.err.println("Error verifying user password: " + e.getMessage());
            return false;
        }
    }

    // Read the encrypted user password from the file
    public static String readUserPassword() throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(USER_PASSWORD_FILE))) {
            return reader.readLine();
        }
    }

    // Encrypt the admin password using AES
    public static String encryptAdminPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt the admin password using AES
    public static String decryptAdminPassword(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }

    // Store the admin password after encryption
    public static void storeAdminPassword(String password) {
        try {
            String encryptedPassword = encryptAdminPassword(password);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(ADMIN_PASSWORD_FILE))) {
                writer.write(encryptedPassword);
            }
        } catch (Exception e) {
            System.err.println("Error storing admin password: " + e.getMessage());
        }
    }

    // Verify the admin password by comparing the decrypted stored password
    public static boolean verifyAdminPassword(String enteredPassword) {
        try {
            String storedEncryptedPassword = readAdminPassword();
            String decryptedPassword = decryptAdminPassword(storedEncryptedPassword);
            return decryptedPassword.equals(enteredPassword);
        } catch (Exception e) {
            System.err.println("Error verifying admin password: " + e.getMessage());
            return false;
        }
    }

    // Read the encrypted admin password from the file
    public static String readAdminPassword() throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(ADMIN_PASSWORD_FILE))) {
            return reader.readLine();
        }
    }

    // Reset the user password by the admin
    public static void resetUserPassword(Scanner scanner) {
        System.out.print("Enter new user password: ");
        String newPassword = scanner.nextLine();
        storeUserPassword(newPassword);  // Store the new password after encryption
        System.out.println("User password has been reset.");
    }
}