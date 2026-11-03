package com.careercompass.controller;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.careercompass.dto.AuthResponse;
import com.careercompass.dto.LoginRequest;
import com.careercompass.dto.LoginResponse;
import com.careercompass.dto.RegisterRequest;
import com.careercompass.service.RefreshTokenService;
import com.careercompass.service.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class UserController {
    private static final String COOKIE = "refresh_token";
    @Value("${app.cookie.secure}")
    private boolean cookieSecure;

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;

    public UserController(UserService userService, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequest request) {
        userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> loginUser(@Valid @RequestBody LoginRequest request) {
        AuthResponse authResponse = userService.loginUser(request);

        ResponseCookie cookie = ResponseCookie.from(COOKIE, authResponse.refreshToken())
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(refreshTokenService.getTtl())
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(authResponse.loginResponse());

    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue(name = COOKIE, required = false) String refreshToken) {

        
        AuthResponse result = userService.refresh(refreshToken);
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        buildCookie(result.refreshToken(), refreshTokenService.getTtl()).toString())
                .body(result.loginResponse());
    }

    private ResponseCookie buildCookie(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE, value)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(maxAge)
                .build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            @CookieValue(name = COOKIE, required = false) String refreshToken) {

        String accessToken = (authHeader != null && authHeader.startsWith("Bearer "))
                ? authHeader.substring(7)
                : null;
        
        userService.logout(accessToken, refreshToken);
        System.out.println("User logged out successfully");
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, buildCookie("", Duration.ZERO).toString())
                .build();
    }
}
