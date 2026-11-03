package com.careercompass.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.careercompass.security.JwtFilter;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtFilter jwtFilter;

    public SecurityConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                /*
                 * csrf.disable() is safe here because API calls are authorized by the
                 * Authorization
                 * header, not by a cookie. (The refresh cookie is protected by SameSite=Strict
                 * and is only sent to /api/auth.)
                 */
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                /*
                 * STATELESS tells Spring not to create server-side sessions.
                 * The JWT is the only proof of identity.
                 */
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(e -> e.authenticationEntryPoint(
                        (req, res, ex) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED)))
                // authenticationEntryPoint makes unauthenticated requests return a clean 401.
                // Without it, Spring may return 403.
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        /* puts jwtFilter before Spring's own filters */

        return http.build();
    }
}
