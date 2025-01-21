package com.keycloak.config

import org.keycloak.OAuth2Constants
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.KeycloakBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate

@Configuration
class KeycloakAdminConfig {

    @Bean
    fun keycloakAdmin(): Keycloak {
        return KeycloakBuilder.builder()
            .serverUrl("http://localhost:8080")
            .realm("master")
            .grantType(OAuth2Constants.PASSWORD)
            .clientId("admin-cli")
            .username("admin")
            .password("admin")
            .build()
    }

    @Bean
    fun restTemplate(): RestTemplate {
        return RestTemplate()
    }
}