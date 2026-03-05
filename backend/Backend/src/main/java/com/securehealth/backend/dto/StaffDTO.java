package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class StaffDTO {
    private Long userId;
    private String email;
    private String role;
}