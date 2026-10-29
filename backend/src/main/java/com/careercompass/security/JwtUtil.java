package com.careercompass.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private final String secretKey;
    private final long accessTokenTTL;

    public JwtUtil(@Value("${jwt.secret}") String secretKey,
            @Value("${jwt.access-ttl-ms}") long accessTokenTTL) {
        this.secretKey = secretKey;
        this.accessTokenTTL = accessTokenTTL;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(Long userId, String email) {
        Date now = new Date();
        return Jwts.builder()
                .id(UUID.randomUUID().toString()) // jti: used later for the blacklist
                .subject(String.valueOf(userId)) // who the token is for
                .claim("email", email)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + accessTokenTTL))
                .signWith(getSigningKey())
                .compact();
    }
    /** Verifies signature and expiry. Throws JwtException if anything is wrong. */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
