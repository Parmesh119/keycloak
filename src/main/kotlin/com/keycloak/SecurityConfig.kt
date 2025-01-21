package com.keycloak

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.config.Customizer.withDefaults

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/api/login/**", "/api/logout").authenticated() // Require authentication for /api/private/**
                    .anyRequest().permitAll() // Allow all other requests
            }
            .oauth2Login(withDefaults()) // Enable OAuth2 login
            .oauth2Client(withDefaults()) // Enable OAuth2 client
            .build()
    }
}
