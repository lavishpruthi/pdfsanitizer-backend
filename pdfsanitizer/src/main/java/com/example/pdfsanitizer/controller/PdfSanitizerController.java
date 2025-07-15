package com.example.pdfsanitizer.controller;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class PdfSanitizerController {

    @PostMapping("/sanitize")
    public ResponseEntity<byte[]> sanitizePdf(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "password", required = false) String password) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body("No file uploaded.".getBytes());
        }
        if (!"application/pdf".equals(file.getContentType())) {
            return ResponseEntity.badRequest().body("Invalid file type. Only PDFs are allowed.".getBytes());
        }
        if (file.getSize() > 10 * 1024 * 1024) { // 10MB limit
            return ResponseEntity.badRequest().body("File size exceeds 10MB.".getBytes());
        }

        try (PDDocument document = loadDocument(file, password)) {
            // Remove encryption if present
            if (document.isEncrypted()) {
                document.setAllSecurityToBeRemoved(true);
            }

            // Remove JavaScript and other actions
            if (document.getDocumentCatalog().getActions() != null) {
                document.getDocumentCatalog().setActions(null);
            }

            // Process each page to remove annotations (links) and actions
            document.getPages().forEach(page -> {
                try {
                    // Remove all annotations (e.g., links)
                    page.setAnnotations(null);

                    // Remove page-level actions
                    if (page.getActions() != null) {
                        page.setActions(null);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            // Save sanitized PDF to byte array
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            document.close();

            // Return sanitized PDF with dynamic file name
            String sanitizedFileName = file.getOriginalFilename().replaceFirst("(?i)\\.pdf$", "_sanitized.pdf");
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + sanitizedFileName + "\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(baos.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
            String errorMessage = e.getMessage() != null && e.getMessage().contains("password")
                    ? "Incorrect password provided or password required."
                    : "Error processing PDF.";
            return ResponseEntity.badRequest().body(errorMessage.getBytes());
        }
    }

    private PDDocument loadDocument(MultipartFile file, String password) throws IOException {
        if (password != null && !password.isEmpty()) {
            // Try loading with password
            try {
                return PDDocument.load(file.getInputStream(), password);
            } catch (IOException e) {
                throw new IOException("Incorrect password provided.", e);
            }
        } else {
            // Try loading without password
            PDDocument document = PDDocument.load(file.getInputStream());
            if (document.isEncrypted()) {
                document.close();
                throw new IOException("Password-protected PDF requires a password.");
            }
            return document;
        }
    }
}