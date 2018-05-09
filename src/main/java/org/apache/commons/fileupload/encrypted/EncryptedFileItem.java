/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.fileupload.encrypted;

import static java.lang.String.format;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.IOUtils;

import javax.crypto.SecretKey;

/**
 * <p> An implementation of the
 * {@link org.apache.commons.fileupload.FileItem FileItem} interface
 * providing transparent encryption of uploaded data.
 *
 * <p> After retrieving an instance of this class from a {@link
 * EncryptedFileItemFactory} instance (see
 * {@link org.apache.commons.fileupload.servlet.ServletFileUpload
 * #parseRequest(javax.servlet.http.HttpServletRequest)}), you may
 * either request all contents of file at once using {@link #get()} or
 * request an {@link java.io.InputStream InputStream} with
 * {@link #getInputStream()} and process the file without attempting to load
 * it into memory, which may come handy with large files.
 *
 * <p>Temporary files, which are created for file items, should be
 * deleted later on. The best way to do this is using a
 * {@link org.apache.commons.io.FileCleaningTracker}, which you can set on the
 * {@link EncryptedFileItemFactory}. However, if you do use such a tracker,
 * then you must consider the following: Temporary files are automatically
 * deleted as soon as they are no longer needed. (More precisely, when the
 * corresponding instance of {@link java.io.File} is garbage collected.)
 * This is done by the so-called reaper thread, which is started and stopped
 * automatically by the {@link org.apache.commons.io.FileCleaningTracker} when
 * there are files to be tracked.
 * It might make sense to terminate that thread, for example, if
 * your web application ends. See the section on "Resource cleanup"
 * in the users guide of commons-fileupload.</p>
 *
 * @see {@code org.apache.commons.fileupload.disk.DiskFileItem}
 *
 * @since FileUpload 1.4
 */
public class EncryptedFileItem
        extends
        DiskFileItem {


    /**
     * Encryption key
     */
    private final SecretKey key;

    // ----------------------------------------------------------- Constructors

    /**
     * Constructs a new <code>EncryptedFileItem</code> instance.
     *
     * @param fieldName     The name of the form field.
     * @param contentType   The content type passed by the browser or
     *                      <code>null</code> if not specified.
     * @param isFormField   Whether or not this item is a plain form field, as
     *                      opposed to a file upload.
     * @param fileName      The original filename in the user's filesystem, or
     *                      <code>null</code> if not specified.
     * @param sizeThreshold The threshold, in bytes, below which items will be
     *                      retained in memory and above which they will be
     *                      stored as a file.
     * @param repository    The data repository, which is the directory in
     *                      which files will be created, should the item size
     *                      exceed the threshold.
     */
    public EncryptedFileItem(String fieldName,
                             String contentType, boolean isFormField, String fileName,
                             int sizeThreshold, File repository) {
        super(fieldName, contentType, isFormField, fileName, sizeThreshold, repository);
        this.key = Cryptography.generateKey();
    }

    // ------------------------------- Methods from javax.activation.DataSource

    /**
     * Returns an {@link java.io.InputStream InputStream} that can be
     * used to retrieve the contents of the file.
     *
     * @return An {@link java.io.InputStream InputStream} that can be
     * used to retrieve the contents of the file.
     *
     * @throws IOException if an error occurs.
     */
    public InputStream getInputStream()
            throws IOException {
        return Cryptography.decrypt(super.getInputStream(), key);
    }

    /**
     * Returns the size of the file.
     *
     * @return The size of the file, in bytes.
     */
    public long getSize() {
        // NB the data in the DeferredOutputStream will be
        // longer because of the initialisation vector:
        return super.getSize() - Cryptography.IninialisationVectorSize();
    }

    /**
     * Returns the contents of the file as an array of bytes.  If the
     * contents of the file were not yet cached in memory, they will be
     * loaded from the disk storage and cached.
     *
     * @return The contents of the file as an array of bytes
     * or {@code null} if the data cannot be read
     */
    public byte[] get() {
        return Cryptography.decrypt(super.get(), key);
    }

    /**
     * A convenience method to write an uploaded item to disk. The client code
     * is not concerned with whether or not the item is stored in memory, or on
     * disk in a temporary location. They just want to write the uploaded item
     * to a file.
     * <p>
     * This implementation first attempts to rename the uploaded item to the
     * specified destination file, if the item was originally written to disk.
     * Otherwise, the data will be copied to the specified file.
     * <p>
     * This method is only guaranteed to work <em>once</em>, the first time it
     * is invoked for a particular item. This is because, in the event that the
     * method renames a temporary file, that file will no longer be available
     * to copy or rename again at a later time.
     *
     * @param file The <code>File</code> into which the uploaded item should
     *             be stored.
     *
     * @throws Exception if an error occurs.
     */
    public void write(File file) throws Exception {
        if (isInMemory()) {
            super.write(file);
        } else {
            // DiskFileItem caches the size of the file at this point
            // because it then attempts to move the file to the destination.
            // In this implementation, the file will always need decrypting
            // so the original file won't be moved.
            // Therefore we can safely not cache the size (which is a private
            // field in the superclass, so that minimises changes).
            /*
             * The uploaded file is being stored encrypted on disk
             * in a temporary location so must be decrypted into the
             * desired file.
             */
            InputStream in = null;
            OutputStream out = null;
            try {
                in = getInputStream();
                out = new FileOutputStream(file);
                IOUtils.copy(in, out);
            } finally {
                IOUtils.closeQuietly(in);
                IOUtils.closeQuietly(out);
            }
        }
    }

    /**
     * Deletes the underlying storage for a file item, including deleting any
     * associated temporary disk file. Although this storage will be deleted
     * automatically when the <code>FileItem</code> instance is garbage
     * collected, this method can be used to ensure that this is done at an
     * earlier time, thus preserving system resources.
     */
    public void delete() {
        super.clearCachedContent();
        File outputFile = super.getStoreLocation();
        if (outputFile != null && !isInMemory() && outputFile.exists()) {
            outputFile.delete();
        }
    }

    /**
     * Returns an {@link java.io.OutputStream OutputStream} that can
     * be used for storing the contents of the file.
     *
     * @return An {@link java.io.OutputStream OutputStream} that can be used
     *         for storing the contents of the file.
     *
     * @throws IOException if an error occurs.
     */
    public OutputStream getOutputStream()
            throws IOException {
        return Cryptography.encrypt(super.getOutputStream(), key);
    }

    // --------------------------------------------------------- Public methods

    /**
     * EncryptedFileItem doesn't support getting the temp file.
     * This is because the raw file is encrypted, so a simple File.renameTo(...) won't work.
     * This exception is here to avoid getting unexpected results if you call this method.
     * Please use getInputStream() instead. If you know what you're doing, you can call the
     * super method explicitly to get access to the encrypted file.
     *
     * @return This method won't allow you to call it, because you might not be expecting the result.
     * @throws UnsupportedOperationException Because the returned file would be encrypted data.
     */
    public File getStoreLocation() {
        throw new UnsupportedOperationException("EncryptedFileItem doesn't support getting the temp file." +
                "This is because the raw file is encrypted, so a simple File.renameTo(...) won't work." +
                "This exception is here to avoid getting unexpected results if you call this method." +
                "Please use getInputStream() instead. If you know what you're doing, you can call the " +
                "super method explicitly");
    }

    /**
     * This override provides access to the protected superclass method for
     * the benefit of {@link EncryptedFileItemFactory}.
     *
     * @return The {@link java.io.File File} to be used for temporary storage.
     */
    protected File getTempFile() {
        return super.getTempFile();
    }

    /**
     * Returns a string representation of this object.
     *
     * This preserves the behaviour of the superclass implementation, but avoids calling the public
     * getStoreLocation, which would require creating a decrypted copy of the file.
     *
     * @return a string representation of this object.
     */
    @Override
    public String toString() {
        return format("name=%s, StoreLocation=%s, size=%s bytes, isFormField=%s, FieldName=%s",
                getName(), super.getStoreLocation(), Long.valueOf(getSize()),
                Boolean.valueOf(isFormField()), getFieldName());
    }
}
