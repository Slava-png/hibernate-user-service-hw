package mate.academy.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class HashUtil {
    private static final String HASHING_ALGORITHM = "SHA-256";

    private HashUtil() {
    }

    public static byte[] getSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static String hashPassword(String password, byte[] salt) {
        StringBuilder hashPassword = new StringBuilder();
        try {
            MessageDigest digest = MessageDigest.getInstance(HASHING_ALGORITHM);
            digest.update(salt);
            byte[] bytes = digest.digest(password.getBytes());

            for (byte b: bytes) {
                hashPassword.append(String.format("%02x", b));
            }
            return hashPassword.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Couldn't hash password: " + password
                    + ", with salt: " + Arrays.toString(salt), e);
        }
    }
}
