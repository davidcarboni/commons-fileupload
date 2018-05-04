package org.apache.commons.fileupload.encrypted;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Cryptography {



    /**
     * The name of the cipher algorithm to use for encryption/decryption.
     */
    public static final String CIPHER_ALGORITHM = "AES";
    /**
     * The name of the cipher mode to use for symmetric cryptographic
     * operations.
     */
    public static final String CIPHER_MODE = "CTR";
    /**
     * The name of the padding type to use for symmetric cryptographic
     * operations.
     */
    public static final String CIPHER_PADDING = "NoPadding";

    /**
     * The key size.
     * <p>
     * This is set to 128-bit ("standard") key length (rather that 256 "strong")
     * because we can't be sure that the
     * 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'
     * are installed. This field is not final, allowing it to be changed to 192 or 256
     * if needed.
     * <p>
     * It's possible to alter this behaviour automatically, but for the sake of clean,
     * readable code and to minimise risks from complicatedness, a modifiable key
     * length of 128 is a pragmatic balance between security and usability.
     */
    public static int KEY_SIZE = 128;

    /**
     * The full name of the {@link Cipher} to use for cryptographic operations,
     * in a format suitable for passing to the JCE.
     */
    public static final String JCE_CIPHER_NAME =
            CIPHER_ALGORITHM + "/" + CIPHER_MODE + "/" + CIPHER_PADDING;

    /**
     * The algorithm for {@link SecureRandom} instances.
     */
    public static final String RANDOM_ALGORITHM = "SHA1PRNG";

    /**
     * This method wraps the destination {@link OutputStream} with a
     * {@link CipherOutputStream}.
     * <p>
     * Typical usage is when you have an InputStream for a source of unencrypted
     * data, such as a user-uploaded file, and an OutputStream to write the
     * input to. You would call this method to wrap the OutputStream and
     * use the returned {@link CipherOutputStream} instead to write the data to,
     * so that it is encrypted as it is written to disk.
     * <p>
     * Note that this method writes an initialisation vector to the destination
     * OutputStream, so the destination parameter will have some bytes written
     * to it before this method returns. These bytes are necessary for
     * decryption and a corresponding call to
     * {@link #decrypt(InputStream, SecretKey)} will read and filter them out
     * from the underlying InputStream before returning it.
     *
     * @param destination The output stream to be wrapped with a
     *                    {@link CipherOutputStream}.
     * @param key         The key to be used to encrypt data written to the returned
     *                    {@link CipherOutputStream}.
     * @return A {@link CipherOutputStream}, which wraps the given
     * {@link OutputStream}.
     * @throws IOException If an error occurs in writing the initialisation vector to
     * the destination stream.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM} key.
     * @see #decrypt(InputStream, SecretKey)
     */
    public static OutputStream encrypt(OutputStream destination, SecretKey key) throws IOException {

        // Initialise a cipher instance with a random IV
        Cipher cipher = getCipher();
        byte[] iv = generateInitialisationVector(cipher);
        initCipher(cipher, Cipher.ENCRYPT_MODE, key, iv);

        // Wrap the stream with a CipherOutputStream:
        CipherOutputStream cipherOutputStream = new CipherOutputStream(destination, cipher);

        // It's safe to store the IV unencrypted at the start of the stream:
        destination.write(iv);

        // Return the wrapping stream:
        return cipherOutputStream;
    }


    /**
     * This method wraps the source {@link InputStream} with a
     * {@link CipherInputStream}.
     * <p>
     * Typical usage is when you have an InputStream for a source of encrypted
     * data on disk, and an OutputStream to send the file to an HTTP response.
     * You would call this method to wrap the InputStream and use the returned
     * {@link CipherInputStream} to read the data from instead so that it is
     * decrypted as it is read and can be written to the response unencrypted.
     * <p>
     * Note that this method reads and discards the random initialisation vector
     * from the source InputStream, so the source parameter will have some bytes
     * read from it before this method returns. These bytes are necessary for
     * decryption and the call to {@link #encrypt(OutputStream, SecretKey)} will
     * have added these to the start of the underlying data automatically.
     *
     * @param input The source {@link InputStream}, containing encrypted data.
     * @param key    The key to be used for decryption.
     * @return A {@link CipherInputStream}, which wraps the given source stream
     * and will decrypt the data as they are read.
     * @throws IOException              If an error occurs in reading the initialisation vector from
     *                                  the source stream.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #encrypt(OutputStream, SecretKey)
     */
    public static InputStream decrypt(InputStream input, SecretKey key) throws IOException {

        // Initialise a cipher instance
        // NB the IV is stored unencrypted at the start of the stream:
        Cipher cipher = getCipher();
        byte[] iv = readInitialisationVector(cipher, input);
        initCipher(cipher, Cipher.DECRYPT_MODE, key, iv);

        // Wrap the stream with a cipherInputStream:
        CipherInputStream cipherInputStream = new CipherInputStream(input, cipher);

        // Return the wrapping stream:
        return cipherInputStream;
    }


    /**
     * Generates a new secret (also known as symmetric) key for use with {@value CIPHER_ALGORITHM}.
     * <p>
     * The key size is determined by {@link #KEY_SIZE}.
     *
     * @return A new, randomly generated secret key.
     */
    public static SecretKey generateKey() {

        // FYI: AES keys are just random bytes from a strong source of randomness.
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Required algorithm unavailable in this JVM: "
                        + CIPHER_ALGORITHM, e);
        }
    }


    /**
     * Initialises the cipher for encryption or decryption.
     * <p>
     * This step has been extracted into a method because the exception handling makes it
     * harder to read the encrypt/decrypt methods.
     * @return A {@link Cipher} instance for {@value JCE_CIPHER_NAME}.
     *
     * @param cipher The {@link Cipher} instance.
     * @param mode One of {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}.
     * @param key The encryption key.
     * @param iv The initialisation vector.
     */
    private static void initCipher(Cipher cipher, int mode, SecretKey key, byte[] iv) {
        // NB the exceptions below should never be thrown if this is
        // called properly using the constants in this class.
        try {
            cipher.init(mode, key, new IvParameterSpec(iv));
        } catch (InvalidKeyException e) {
            String message = "The given key is not supported by this JVM for: "
                    + JCE_CIPHER_NAME;
            if (KEY_SIZE > 128) {
                message += ". You may need to install the " +
                        "'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'";
            }
            throw new IllegalArgumentException(message, e);
        } catch (InvalidAlgorithmParameterException e) {
            String message = "The parameters provided are invalid for: "
                    + JCE_CIPHER_NAME;
        }
    }

    /**
     * Generates a cipher instance for {@value CIPHER_ALGORITHM}.
     * <p>
     * This step has been extracted into a method because the exception handling makes it
     * harder to read the encrypt/decrypt methods.
     * @return A {@link Cipher} instance for {@value JCE_CIPHER_NAME}.
     */
    private static Cipher getCipher() {
        // NB the exceptions below should never be thrown if this is
        // called properly using the constants in this class.
        try {
            return Cipher.getInstance(JCE_CIPHER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("The required encryption algorithm is not available: "
                    + JCE_CIPHER_NAME);
        } catch (NoSuchPaddingException e) {
            throw new IllegalArgumentException("The required padding method is not supported: "
                    + JCE_CIPHER_NAME);
        }
    }


    /**
     * This method generates a random initialisation vector. The length of the
     * IV is determined by calling {@link Cipher#getBlockSize()} on the given cipher.
     *
     * @return A byte array, of a size corresponding to the block size of the
     * given {@link Cipher}, containing random bytes.
     */
    private static byte[] generateInitialisationVector(Cipher cipher) throws IOException {

        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstance(RANDOM_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unable to generate bytes using SecureRandom algorithm: "
                    + RANDOM_ALGORITHM);
        }
        int ivSize = cipher.getBlockSize();
        byte[] bytes = new byte[ivSize];
        secureRandom.nextBytes(bytes);
        return bytes;
    }


    /**
     * This method generates a random initialisation vector. The length of the
     * IV is determined by calling {@link Cipher#getBlockSize()} on the given cipher.
     *
     * @param source The stream to read the IV from.
     * @return A byte array, of a size corresponding to the block size of the
     * given {@link Cipher}, containing random bytes.
     */
    private static byte[] readInitialisationVector(Cipher cipher, InputStream source) throws IOException {
        int ivSize = cipher.getBlockSize();
        byte[] bytes = new byte[ivSize];
        int read = 0;
        while (read < bytes.length) {
            read += source.read(bytes, read, bytes.length - read);
        }
        return bytes;
    }

}
