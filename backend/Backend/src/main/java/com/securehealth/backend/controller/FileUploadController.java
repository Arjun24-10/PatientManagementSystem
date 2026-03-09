package com.securehealth.backend.controller;

import com.securehealth.backend.service.FileStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping("/api/files")
public class FileUploadController {

    @Autowired
    private FileStorageService fileStorageService;

    /**
     * Upload a file (image or document). The file is encrypted at rest using AES-256-GCM.
     * Returns the unique filename for linking to medical records.
     */
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            String filename = fileStorageService.storeFile(file);
            return ResponseEntity.ok(Map.of(
                    "message", "File uploaded and encrypted successfully.",
                    "filename", filename
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    /**
     * Retrieve and decrypt a stored file by its filename.
     */
    @GetMapping("/{filename}")
    public ResponseEntity<?> getFile(@PathVariable String filename) {
        try {
            byte[] fileData = fileStorageService.loadFile(filename);
            String extension = fileStorageService.getOriginalExtension(filename);

            MediaType mediaType = getMediaType(extension);

            return ResponseEntity.ok()
                    .contentType(mediaType)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + filename.replace(".enc", "") + "\"")
                    .body(fileData);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    private MediaType getMediaType(String extension) {
        return switch (extension.toLowerCase()) {
            case "jpg", "jpeg" -> MediaType.IMAGE_JPEG;
            case "png" -> MediaType.IMAGE_PNG;
            case "gif" -> MediaType.IMAGE_GIF;
            case "pdf" -> MediaType.APPLICATION_PDF;
            default -> MediaType.APPLICATION_OCTET_STREAM;
        };
    }
}
