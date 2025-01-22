package com.keycloak.config

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter

class KeycloakJwtAuthenticationConverter : JwtAuthenticationConverter() {

    init {
        // Set the custom JwtGrantedAuthoritiesConverter to extract roles from the JWT
        setJwtGrantedAuthoritiesConverter { jwt: Jwt ->
            extractAuthorities(jwt)
        }
    }

    private fun extractAuthorities(jwt: Jwt): Collection<SimpleGrantedAuthority> {
        val realmRoles = jwt.getClaim<Map<String, Any>>("realm_access")?.get("roles") as? List<String> ?: emptyList()

        // Log roles for debugging
        println("Roles extracted: $realmRoles")

        return realmRoles.map { role -> SimpleGrantedAuthority("ROLE_$role") }
    }
}
