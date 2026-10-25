package com.careercompass.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank(message = "Name is required")
    @Size(min=2,max=50,message="Name must be 2-50 characters long")
    String name, 

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")    
    String email, 

    @Size (min=8,max=64,message="Password must be 8-64 characters long")
    @NotBlank(message = "Password is required")
    String password) {

    
}
