package com.securehealth.backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Service for storing and retrieving encrypted files.
 * Uses AES-256-GCM for encryption at rest.
 * The storage directory is configurable — point it to a local path or a mounted network/S3 volume.
 */
@Service
public class FileStorageService {

    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private static final List<String> ALLOWED_EXTENSIONS = List.of(
            "jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "txt", "csv"
    );

    @Value("${app.upload.dir:./uploads}")
    private String uploadDir;

    @Value("${app.encryption.key}")
    private String encryptionKeyBase64;

    /**
     * Stores an uploaded file with AES-256-GCM encryption at rest.
     * <p>
     * Validates the file extension against an allowlist and generates a 
     * unique filename for secure storage.
     * </p>
     *
     * @param file the {@link MultipartFile} to store
     * @return the unique filename generated for the stored file
     * @throws IOException if an I/O error occurs during storage
     * @throws RuntimeException if the file is empty or the type is not allowed
     */
    public String storeFile(MultipartFile file) throws IOException {
        // 1. Validate
        if (file.isEmpty()) {
            throw new RuntimeException("Cannot upload empty file.");
        }

        String originalName = file.getOriginalFilename();
        String extension = getExtension(originalName);

        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new RuntimeException("File type not allowed: " + extension
                    + ". Allowed: " + String.join(", ", ALLOWED_EXTENSIONS));
        }

        // 2. Generate unique filename
        String uniqueFilename = UUID.randomUUID() + "." + extension + ".enc";

        // 3. Ensure upload directory exists
        Path dirPath = Paths.get(uploadDir);
        if (!Files.exists(dirPath)) {
            Files.createDirectories(dirPath);
        }

        // 4. Encrypt and save
        try {
            byte[] plainBytes = file.getBytes();
            byte[] encryptedBytes = encrypt(plainBytes);
            Files.write(dirPath.resolve(uniqueFilename), encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt and store file: " + e.getMessage(), e);
        }

        return uniqueFilename;
    }

    /**
     * Retrieves and decrypts a stored file based on its filename.
     *
     * @param filename the unique name of the encrypted file
     * @return the decrypted byte array of the file content
     * @throws IOException if an I/O error occurs during retrieval
     * @throws RuntimeException if the file is not found or decryption fails
     */
    public byte[] loadFile(String filename) throws IOException {
        Path filePath = Paths.get(uploadDir).resolve(filename);

        if (!Files.exists(filePath)) {
            throw new RuntimeException("File not found: " + filename);
        }

        try {
            byte[] encryptedBytes = Files.readAllBytes(filePath);
            return decrypt(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt file: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the original file extension from an encrypted filename.
     * e.g., "uuid.pdf.enc" → "pdf"
     */
    public String getOriginalExtension(String encryptedFilename) {
        // Strip .enc suffix, then get the real extension
        String withoutEnc = encryptedFilename.replace(".enc", "");
        return getExtension(withoutEnc);
    }

    // --- Encryption ---

    private byte[] encrypt(byte[] data) throws Exception {
        SecretKey key = getKey();
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] cipherText = cipher.doFinal(data);

        // Prepend IV to ciphertext for storage: [IV | ciphertext]
        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

        return result;
    }

    private byte[] decrypt(byte[] data) throws Exception {
        SecretKey key = getKey();

        // Extract IV from first 12 bytes
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(data, 0, iv, 0, GCM_IV_LENGTH);

        // Extract ciphertext
        byte[] cipherText = new byte[data.length - GCM_IV_LENGTH];
        System.arraycopy(data, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        return cipher.doFinal(cipherText);
    }

    private SecretKey getKey() {
        byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private String getExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "";
        }
        return filename.substring(filename.lastIndexOf('.') + 1);
    }
}
