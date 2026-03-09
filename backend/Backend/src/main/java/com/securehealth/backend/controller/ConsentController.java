package com.securehealth.backend.controller;

import com.securehealth.backend.model.Consent;
import com.securehealth.backend.service.ConsentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/consent")
@PreAuthorize("hasAuthority('PATIENT')")
public class ConsentController {

    @Autowired
    private ConsentService consentService;

    /**
     * GET /api/consent — List all consents for the logged-in patient.
     */
    @GetMapping
    public ResponseEntity<?> getMyConsents(Authentication authentication) {
        return ResponseEntity.ok(consentService.getMyConsents(authentication.getName()));
    }

    /**
     * POST /api/consent — Grant a new consent.
     * Body: { "grantedToId": 5, "consentType": "MEDICAL_RECORDS", "reason": "...", "expiresAt": "..." }
     */
    @PostMapping
    public ResponseEntity<?> grantConsent(@RequestBody Map<String, Object> payload, Authentication authentication) {
        Consent consent = consentService.grantConsent(authentication.getName(), payload);
        return ResponseEntity.status(201).body(consent);
    }

    /**
     * PUT /api/consent/{id}/revoke — Revoke a consent.
     */
    @PutMapping("/{id}/revoke")
    public ResponseEntity<?> revokeConsent(@PathVariable Long id, Authentication authentication) {
        Consent consent = consentService.revokeConsent(authentication.getName(), id);
        return ResponseEntity.ok(consent);
    }
}
