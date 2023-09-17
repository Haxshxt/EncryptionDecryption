import java.io.*;
import java.util.Scanner;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.*;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.*;

public class EncryptionDecryption {
    public static void encryptDecrypt(String key, int cipherMode, File in, File out)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            IOException {
        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(out);

        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());

        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = skf.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, SecureRandom.getInstance("SHA1PRNG"));
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            write(cis, fos);
        } else if (cipherMode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, SecureRandom.getInstance("SHA1PRNG"));
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            write(fis, cos);
        }
    }

    private static void write(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[64];
        int numOfBytesRead;
        while ((numOfBytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, numOfBytesRead);
        }
        out.close();
        in.close();
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("For encryption enter choice as 1: ");
        System.out.println("For decryption enter choice as 2: ");
        int choice = sc.nextInt();
        File plaintext = new File("");
        File encrypted = new File("");
        
        if (choice == 1) {
            try {
                encryptDecrypt("12345678", Cipher.ENCRYPT_MODE, plaintext, encrypted);
                System.out.println("Encryption complete");

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if (choice == 2) {
            File encryptedFile = new File(""); // Replace with the actual path to the encrypted file
            File decryptedFile = new File(""); // Replace with the actual path for the decrypted file

            try {
                encryptDecrypt("12345678", Cipher.DECRYPT_MODE, encryptedFile, decryptedFile);
                System.out.println("Decryption Complete:");
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException |
                    NoSuchPaddingException | IOException e) {
                e.printStackTrace();
            }
        }
    }
}
