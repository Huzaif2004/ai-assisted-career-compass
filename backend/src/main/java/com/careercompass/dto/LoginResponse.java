package com.careercompass.dto;

public record LoginResponse(
    String jwtToken,
    String email,
    String name
) {

    
}
