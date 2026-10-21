package com.scamshield_backend;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/scan/**", "/api/admin/**", "/api/community/**"))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/scan/**", "/api/admin/**", "/api/community/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }
}