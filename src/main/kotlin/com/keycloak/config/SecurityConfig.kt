package com.keycloak.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.config.Customizer.withDefaults

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/api/public/**", "/api/get-access").permitAll()
                    .requestMatchers("/api/users/**").hasRole("default-roles-master")
                    .requestMatchers("/api/**").authenticated()
                    .anyRequest().permitAll()
            }
//            .oauth2ResourceServer { oauth2 ->
//                oauth2.jwt { jwt ->
//                    jwt.jwtAuthenticationConverter(KeycloakJwtAuthenticationConverter()) // Use custom converter
//                }
//            }
            .addFilterAfter(CustomSecurityFilter(), BasicAuthenticationFilter::class.java)
            .oauth2Login(withDefaults())
            .oauth2Client(withDefaults())
            .build()
    }

    @Bean
    fun jwtDecoder(@Value("\${spring.security.oauth2.client.provider.keycloak.issuer-uri}") issuerUri: String): JwtDecoder {
        return NimbusJwtDecoder.withIssuerLocation(issuerUri).build()
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val converter = JwtGrantedAuthoritiesConverter()
        converter.setAuthorityPrefix("ROLE_")
        converter.setAuthoritiesClaimName("roles") // Customize to match Keycloak claims
        return JwtAuthenticationConverter().apply {
            setJwtGrantedAuthoritiesConverter(converter)
        }
    }
}
