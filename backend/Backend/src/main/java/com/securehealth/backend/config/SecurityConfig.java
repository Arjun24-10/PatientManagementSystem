package com.securehealth.backend.config;

import com.securehealth.backend.model.AuditLog;
import com.securehealth.backend.repository.AuditLogRepository;
import com.securehealth.backend.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Value;
import java.util.Arrays;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.List;

/**
 * Configuration class for Spring Security.
 * <p>
 * This class defines the security filter chain, password encoding, CORS configuration, 
 * and authorization rules for the application. It also integrates JWT-based authentication
 * and provides custom handling for unauthorized and forbidden access attempts.
 * </p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Value("${app.cors.allowed-origins:http://localhost:3000}")
    private String allowedOrigins;

    /**
     * Defines the {@link PasswordEncoder} bean using the Argon2 algorithm.
     *
     * @return an {@link Argon2PasswordEncoder} instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 4096, 3);
    }

    /**
     * Configures the {@link SecurityFilterChain} for the application.
     * <p>
     * This method defines CSRF protection, session management, CORS settings, 
     * request authorization, and custom exception handling for authentication and access denial.
     * It also adds the {@link JwtAuthenticationFilter} before the standard username/password filter.
     * </p>
     *
     * @param http the {@link HttpSecurity} object to configure
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)

                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/admin/**").hasAuthority("ADMIN")
                        .anyRequest().authenticated()
                )

                // 🔐 PROMINENT SECURITY LOGGING
                .exceptionHandling(ex -> ex

                        // 401 - UNAUTHORIZED
                        .authenticationEntryPoint((request, response, authException) -> {

                            saveSecurityLog("UNAUTHORIZED_ACCESS", request);

                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                        })

                        // 403 - FORBIDDEN
                        .accessDeniedHandler((request, response, accessDeniedException) -> {

                            saveSecurityLog("FORBIDDEN_ACCESS", request);

                            response.sendError(HttpServletResponse.SC_FORBIDDEN);
                        })
                )

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Saves a security log entry for unauthorized or forbidden access attempts.
     *
     * @param action  the security action being logged (e.g., "UNAUTHORIZED_ACCESS")
     * @param request the {@link HttpServletRequest} associated with the attempt
     */
    private void saveSecurityLog(String action, HttpServletRequest request) {
        try {
            AuditLog log = new AuditLog(
                    "SYSTEM",   // ✅ Never null
                    action,
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent"),
                    request.getRequestURI()
            );

            auditLogRepository.save(log);

        } catch (Exception ignored) {
            // Security logging should never break request flow
        }
    }

    /**
     * Configures the CORS (Cross-Origin Resource Sharing) settings.
     * <p>
     * This method specifies allowed origins, methods, headers, and credential support 
     * based on application properties and standard requirements.
     * </p>
     *
     * @return a {@link CorsConfigurationSource} for use in the security filter chain
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Split by comma and trim whitespace
        String[] origins = allowedOrigins.split(",");
        configuration.setAllowedOrigins(Arrays.stream(origins).map(String::trim).toList());
        
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}