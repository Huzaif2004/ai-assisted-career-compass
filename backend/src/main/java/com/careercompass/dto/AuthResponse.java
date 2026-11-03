package com.careercompass.dto;

public record AuthResponse(LoginResponse loginResponse, String refreshToken) {}