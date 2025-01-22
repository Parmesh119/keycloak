package com.keycloak

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/api/login/**", "/api/logout").authenticated()
                    .anyRequest().permitAll() // Allow all other requests
            }
            .addFilterAfter(CustomSecurityFilter(), BasicAuthenticationFilter::class.java)
            .oauth2Login(withDefaults())
            .oauth2Client(withDefaults())
            .build()
    }
}
