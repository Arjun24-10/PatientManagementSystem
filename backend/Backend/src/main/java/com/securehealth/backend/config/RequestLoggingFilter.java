package com.securehealth.backend.config;

import com.securehealth.backend.model.AuditLog;
import com.securehealth.backend.repository.AuditLogRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        long start = System.currentTimeMillis();

        filterChain.doFilter(request, response);

        long duration = System.currentTimeMillis() - start;

        String uri = request.getRequestURI();
        int status = response.getStatus();

        // 🔥 Extract authenticated user email
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = "ANONYMOUS";

        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            email = auth.getName();
        }

        String ip = request.getRemoteAddr();
        String agent = request.getHeader("User-Agent");

        try {

            // 🔹 Only log if user is authenticated
            if (auth != null && auth.isAuthenticated()
                    && !"anonymousUser".equals(auth.getPrincipal())
                    && !uri.startsWith("/api/auth")) {

                String readableDetails = null;

                if (status >= 500) {
                    readableDetails = "System error occurred while accessing " + uri;
                }
                else if (status == 403) {
                    readableDetails = "Attempted to access restricted resource: " + uri;
                }
                else if (status == 401) {
                    readableDetails = "Unauthorized access attempt to " + uri;
                }
                else if (status >= 400) {
                    readableDetails = "Invalid request made to " + uri;
                }
                else if (status == 200) {
                    readableDetails = "Successfully accessed " + uri;
                }

                if (readableDetails != null) {
                    auditLogRepository.save(
                            new AuditLog(email, "API_ACTIVITY", ip, agent, readableDetails)
                    );
                }
            }

        } catch (Exception e) {
            System.err.println("Audit logging failed: " + e.getMessage());
        }
    }
}