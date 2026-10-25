package com.careercompass.model;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
@Entity
@Table(name = "users",
    uniqueConstraints = {
        @jakarta.persistence.UniqueConstraint(columnNames = "email")
    })

public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Name is required")
    @Column(nullable = false)
    private String name;

    @Email(message = "Invalid email address")
    @Column(nullable = false)
    private String email;

    //Hashed B-crypt password is always 60 characters long
    @NotBlank(message = "Password is required")
    @Column(name="hashed_password",nullable = false)
    private String hashedPassword;

    private Instant createdAt=Instant.now();
    protected User() {}

    // getters & setters

    public User(String name,String email, String hashedPassword) {
        this.name = validateText(name);
        this.email = validateEmail(email);
        this.hashedPassword = validateText(hashedPassword);
    }

    public String getEmail() {
        return email;
    }
    
    public String getHashedassword() {
        return hashedPassword;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
    public String validateText(String text) {
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("Text cannot be null or empty");
        }
        return text.trim();
    }
    public String validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
        // Basic email format validation
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        if (!email.matches(emailRegex)) {
            throw new IllegalArgumentException("Invalid email format");
        }
        return email.trim();
    }
    
    
}
