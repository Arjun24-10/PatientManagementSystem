package com.securehealth.backend.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleRuntimeException(RuntimeException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", ex.getMessage());
        
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        
        if (ex.getMessage() != null) {
            if (ex.getMessage().contains("404")) {
                status = HttpStatus.NOT_FOUND;
            } else if (ex.getMessage().contains("400")) {
                status = HttpStatus.BAD_REQUEST;
            } else if (ex.getMessage().contains("403")) {
                status = HttpStatus.FORBIDDEN;
            } else if (ex.getMessage().contains("401")) {
                status = HttpStatus.UNAUTHORIZED;
            }
        }
        
        return new ResponseEntity<>(response, status);
    }
}
