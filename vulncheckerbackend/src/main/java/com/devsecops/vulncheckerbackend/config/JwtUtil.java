package com.devsecops.vulncheckerbackend.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey secretKey;
    private final long expirationMs;

    public JwtUtil(@Value("${jwt.secret:}") String encodedSecret,
                   @Value("${jwt.expiration-ms:86400000}") long expirationMs) {
        if (encodedSecret == null || encodedSecret.isBlank()) {
            throw new IllegalStateException("JWT secret is not configured. Set 'jwt.secret' in application properties.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(encodedSecret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
    }

    public String generateToken(String email, String role, Long userId, String firstName) {
        return Jwts.builder()
                .subject(email)
                .claim("role", role)
                .claim("userId", userId)
                .claim("name", firstName)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(secretKey)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getEmailFromToken(String token) {
        return validateToken(token).getSubject();
    }

    public String getRoleFromToken(String token) {
        return validateToken(token).get("role", String.class);
    }
}
