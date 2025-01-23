package com.keycloak.config

import org.keycloak.OAuth2Constants
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.KeycloakBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.ClientHttpRequestFactory
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.web.client.RestTemplate

@Configuration
class KeycloakAdminConfig {

    @Bean
    fun keycloakAdmin(): Keycloak {
        return KeycloakBuilder.builder()
            .serverUrl("http://localhost:8080")
            .realm("master")
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .clientId("config")  // Use your client ID
            .clientSecret("Qg0Z29EOtioDLSVVaiQSCW2OYE26Ms9S")  // Use your client secret
            .username("parmesh")
            .password("admin")
            .build()
    }

    @Bean
    fun restTemplate(): RestTemplate {
        val restTemplate = RestTemplate()
        // Add FormHttpMessageConverter
        restTemplate.messageConverters.add(FormHttpMessageConverter())
        return restTemplate
    }

    private fun simpleClientHttpRequestFactory(): ClientHttpRequestFactory {
        return SimpleClientHttpRequestFactory()
    }
}