package com.careercompass.service.implementation;

import java.sql.SQLException;
import java.util.Locale;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.careercompass.dto.AuthResponse;
import com.careercompass.dto.LoginRequest;
import com.careercompass.dto.LoginResponse;
import com.careercompass.dto.RegisterRequest;
import com.careercompass.dto.RotationResult;
import com.careercompass.exceptions.InvalidEmailException;
import com.careercompass.exceptions.InvalidPasswordException;
import com.careercompass.exceptions.InvalidTokenException;
import com.careercompass.exceptions.UserAlreadyExistsException;
import com.careercompass.model.User;
import com.careercompass.repository.UserRepository;
import com.careercompass.security.JwtUtil;
import com.careercompass.service.RefreshTokenService;
import com.careercompass.service.TokenBlackListService;
import com.careercompass.service.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlackListService blackListService;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService, TokenBlackListService blackListService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.blackListService = blackListService;
    }

    @Override
    public void registerUser(RegisterRequest request) {
        // Check if the email is already registered
        String emailLowercase = request.email().toLowerCase(Locale.ROOT);
        if (userRepository.findByEmail(emailLowercase).isPresent()) {
            throw new UserAlreadyExistsException("Email is already registered");
        }

        // Create a new User entity and save it to the database
        User user = new User(request.name(), emailLowercase, passwordEncoder.encode(request.password()));

        try {

            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            if (isEmailUniqueConstraintViolation(e)) {
                throw new UserAlreadyExistsException("Email is already registered");
            }
            throw e;
        }
    }

    private boolean isEmailUniqueConstraintViolation(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException violation
                    && User.EMAIL_UNIQUE_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName())) {
                return true;
            }

            if (cause instanceof SQLException sqlException
                    && sqlException.getErrorCode() == 1062
                    && sqlException.getMessage() != null
                    && sqlException.getMessage().toLowerCase(Locale.ROOT)
                            .contains(User.EMAIL_UNIQUE_CONSTRAINT.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public AuthResponse loginUser(LoginRequest request) {
        if (request.email() == null || request.password() == null) {
            throw new IllegalArgumentException("Email and password must not be null");
        }
        String emailLowercase = request.email().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmail(emailLowercase)
                .orElseThrow(() -> new InvalidEmailException("Invalid email"));

        if (!passwordEncoder.matches(request.password(), user.getHashedPassword())) {
            throw new InvalidPasswordException("Invalid password");
        }

        String jwtToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = refreshTokenService.issueRefreshToken(user.getId());
        return new AuthResponse(new LoginResponse(jwtToken, user.getEmail(), user.getName()), refreshToken);
    }

    @Override
    public AuthResponse refresh(String refreshToken) {
        RotationResult result = refreshTokenService.rotate(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired refresh token"));

        User user = userRepository.findById(result.userId())
                .orElseThrow(() -> new InvalidTokenException("User not found for the given refresh token"));
        String jwtToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        return new AuthResponse(new LoginResponse(jwtToken, user.getEmail(), user.getName()), result.newRawToken());
    }

    @Override
    public void logout(String accessToken, String refreshToken) {
        refreshTokenService.revoke(refreshToken);
        if (accessToken != null) {
        try {
            Claims claims = jwtUtil.parse(accessToken);
            System.out.println("Blacklisting access token for user ID: " + claims.getId() + " with expiration: " + claims.getExpiration());
            blackListService.blackList(claims.getId(), claims.getExpiration());
        } catch (JwtException | IllegalArgumentException e) {
            // expired or invalid: nothing to blacklist
        }
    }
    }

}
