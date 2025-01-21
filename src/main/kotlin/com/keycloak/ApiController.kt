package com.keycloak

import com.nimbusds.openid.connect.sdk.claims.UserInfo
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class ApiController {

    @GetMapping("/")
    fun getRootRoute(): String {
        return "This is the root route. No authentication required."
    }

    @GetMapping("/public")
    fun getPublicRoute(): String {
        return "This is a public route. No authentication required."
    }

    @GetMapping("/private")
    fun getPrivateRoute(): ResponseEntity<UserInfo> {
        val authentication = SecurityContextHolder.getContext().authentication

        return if (authentication != null && authentication.isAuthenticated) {
            val oidcUser = authentication.principal as? OidcUser
            val userInfo = UserInfo(
                name = oidcUser?.fullName ?: authentication.name,
                email = oidcUser?.email ?: "",
                roles = authentication.authorities.map { it.authority },
                claims = oidcUser?.claims?.filterKeys {
                    it in setOf("given_name", "family_name", "email_verified", "preferred_username")
                } ?: emptyMap()
            )
            ResponseEntity.ok(userInfo)
        } else {
            ResponseEntity.status(401).build()
        }
    }
    data class UserInfo(
        val name: String,
        val email: String,
        val roles: List<String>,
        val claims: Map<String, Any>
    )
}