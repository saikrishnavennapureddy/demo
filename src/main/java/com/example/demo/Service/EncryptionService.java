package com.example.demo.Service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String SALT = "sai";  // Fixed salt
    private static final String SECRET = "superSecretPassword"; // Secret password for key derivation
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128;

    // Random IV for AES CBC mode
    private IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private SecretKeySpec getKeyFromPassword() throws Exception {
        PBEKeySpec spec = new PBEKeySpec(SECRET.toCharArray(), SALT.getBytes(), ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    public String encrypt(String input) throws Exception {
        SecretKeySpec key = getKeyFromPassword();
        IvParameterSpec iv = generateIv();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(input.getBytes());
        byte[] ivBytes = iv.getIV();

        // Combine IV + ciphertext
        byte[] combined = new byte[ivBytes.length + encrypted.length];
        System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
        System.arraycopy(encrypted, 0, combined, ivBytes.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public String decrypt(String input) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(input);

        byte[] iv = new byte[16];
        byte[] cipherText = new byte[decoded.length - 16];

        System.arraycopy(decoded, 0, iv, 0, 16);
        System.arraycopy(decoded, 16, cipherText, 0, cipherText.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec key = getKeyFromPassword();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted);
    }
}
