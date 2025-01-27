package com.keycloak.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.config.Customizer.withDefaults

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/api/public/**", "/api/get-access", "/api/users/list", "/api/admin", "/api/users/create", "/api/users/update", "/api/users/delete/{id}", "/api/users/{id}", "/api/verify-token", "/api/users/list/client", "/api/users/list/client/{id}", "/api/login", "/api/logout", "/api/refresh-token", "/api/reset/password", "/api/users").permitAll()
                    .requestMatchers("/api/users/**").hasRole("default-roles-master")
                    .requestMatchers("/api/**").authenticated()
                    .anyRequest().permitAll()
            }
//            .addFilterAfter(CustomSecurityFilter(), BasicAuthenticationFilter::class.java)
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt ->
                    jwt.jwtAuthenticationConverter(KeycloakJwtAuthenticationConverter()) // Use custom converter
                }
            }
            .oauth2Login(withDefaults())
            .oauth2Client(withDefaults())
            .build()
    }

    @Bean
    fun jwtDecoder(@Value("\${spring.security.oauth2.client.provider.keycloak.issuer-uri}") issuerUri: String): JwtDecoder {
        return NimbusJwtDecoder.withIssuerLocation(issuerUri).build()
    }
}
