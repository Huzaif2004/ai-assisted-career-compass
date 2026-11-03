package com.careercompass.security;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.careercompass.service.TokenBlackListService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final TokenBlackListService blackListService;

    public JwtFilter(JwtUtil jwtUtil, TokenBlackListService blackListService) {
        this.jwtUtil = jwtUtil;
        this.blackListService = blackListService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); 
            try {
                Claims claims = jwtUtil.parse(token);

                if (blackListService.isBlackListed(claims.getId())) {
                    chain.doFilter(request, response); // stays unauthenticated
                    return;
                }
                var authentication = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(), // principal = user id as a string
                        null,
                        List.of()); // authorities (roles) come later

                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (JwtException | IllegalArgumentException e) {
                // bad or expired token: do nothing, request stays unauthenticated
            }
        }

        chain.doFilter(request, response); 
    }
}