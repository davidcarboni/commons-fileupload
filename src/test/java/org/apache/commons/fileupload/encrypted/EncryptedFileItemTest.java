package org.apache.commons.fileupload.encrypted;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.*;

public class EncryptedFileItemTest {

    static EncryptedFileItemFactory factory = new EncryptedFileItemFactory();
    String fieldName = "file";
    String contentType = "UTF8";
    boolean isFormField = false;
    String fileName = "test.txt";
    FileItem item;

    @Before
    public void setup() {
        item = factory.createItem(fieldName, contentType, isFormField, fileName);
    }


    @Test
    public void testGetInputStreamFromMemory() throws IOException {

        // Given
        // Data small enough that they'll be held in memory
        byte[] data = randomBytes(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD
                - Cryptography.IninialisationVectorSize() - 1);
        item.getOutputStream().write(data);

        // When
        // We get the data
        InputStream decrypted = item.getInputStream();

        // Then
        // We should get decrypted data
        assertStreamEquals(data, decrypted);
    }

    @Test
    public void testGetInputStreamFromDisk() throws IOException {

        // Given
        // Data large enough that they'll be written to disk
        byte[] data = randomBytes(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD);
        item.getOutputStream().write(data);

        // When
        // We get the data
        InputStream decrypted = item.getInputStream();

        // Then
        // We should get decrypted data
        assertStreamEquals(data, decrypted);
    }


    @Test
    public void testGetFromMemory() throws IOException {

        // Given
        // Data small enough that they'll be held in memory
        byte[] data = randomBytes(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD
                - Cryptography.IninialisationVectorSize() - 1);
        item.getOutputStream().write(data);

        // When
        // We get the data
        byte[] decrypted = item.get();

        // Then
        // We should get decrypted data
        assertArrayEquals(data, decrypted);
    }

    @Test
    public void testGetFromDisk() throws IOException {

        // Given
        // Data large enough that they'll be written to disk
        byte[] data = randomBytes(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD);
        item.getOutputStream().write(data);

        // When
        // We get the data
        byte[] decrypted = item.get();

        // Then
        // We should get decrypted data
        assertArrayEquals(data, decrypted);
    }

    @Test
    public void getSizeMemory() throws IOException {

        // Given
        // Data small enough that they'll be held in memory
        byte[] data = randomBytes(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD - 1);
        item.getOutputStream().write(data);

        // When
        // We get the data size
        long size = item.getSize();

        // Then
        // We should get the expected size (not including the IV)
        assertEquals(data.length, size);
    }

    @Test
    public void getSizeDisk() throws IOException {

        // Given
        // Data large enough that they'll be written to disk
        byte[] data = randomBytes(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD + 1);
        item.getOutputStream().write(data);

        // When
        // We get the data size
        long size = item.getSize();

        // Then
        // We should get the expected size (not including the IV)
        assertEquals(data.length, size);
    }

    @Test
    public void write() {
    }

    @Test
    public void delete() {
    }

    @Test
    public void getOutputStream() {
    }

    @Test
    public void getStoreLocation() {
    }

    static byte[] randomBytes(int length) {
        try {
            // An arbitrary value that's not a power of 2
            // To ensure we're doing something
            // a touch more awkward than whole blocks:
            byte[] bytes = new byte[length];
            SecureRandom random = SecureRandom.getInstance(Cryptography.RANDOM_ALGORITHM);
            random.nextBytes(bytes);
            return bytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Compares stream data to an expected sequence of bytes.
     * @param expected The expected byte sequence.
     * @param actual The stream of data.
     * @throws IOException If an error occurs in reading the stream.
     */
    static void assertStreamEquals(byte[] expected, InputStream actual) throws IOException {
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], (byte)actual.read());
        }
        assertEquals(-1, actual.read());
    }
}