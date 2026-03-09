package com.securehealth.backend.exception;

import com.securehealth.backend.dto.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Global Exception Handler for the entire backend.
 * Catches exceptions thrown from any controller and returns
 * a standardized JSON {@link ErrorResponse}.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger =
            LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // --- Validation Errors (e.g., @Valid on DTOs) ---
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.toList());

        ErrorResponse error = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                "One or more fields are invalid.");
        error.setDetails(details);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    // --- Access Denied (Spring Security @PreAuthorize failures) ---
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        ErrorResponse error = new ErrorResponse(
                HttpStatus.FORBIDDEN.value(),
                "Forbidden",
                "You do not have permission to perform this action.");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    // --- JWT: Expired Token ---
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleExpiredJwt(ExpiredJwtException ex) {
        ErrorResponse error = new ErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                "Token Expired",
                "Your session has expired. Please log in again.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    // --- JWT: Malformed or Invalid Signature ---
    @ExceptionHandler({MalformedJwtException.class, SignatureException.class})
    public ResponseEntity<ErrorResponse> handleBadJwt(Exception ex) {
        ErrorResponse error = new ErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                "Invalid Token",
                "The provided authentication token is invalid.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    // --- Illegal Argument (e.g., bad enum values, parsing errors) ---
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
        ErrorResponse error = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    // --- General RuntimeException (catch-all for business logic errors) ---
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> handleRuntime(RuntimeException ex) {
        String message = ex.getMessage() != null ? ex.getMessage() : "An unexpected error occurred.";

        if (message.toLowerCase().contains("not found")) {
            ErrorResponse error = new ErrorResponse(
                    HttpStatus.NOT_FOUND.value(),
                    "Not Found",
                    message);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }

        if (message.contains("409")) {
            ErrorResponse error = new ErrorResponse(
                    HttpStatus.CONFLICT.value(),
                    "Conflict",
                    message);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
        }

        ErrorResponse error = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    // --- Ultimate fallback for truly unexpected errors ---
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAll(Exception ex) {
        ErrorResponse error = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "An unexpected error occurred. Please try again later.");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}