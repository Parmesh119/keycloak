package com.keycloak

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class ApiController(private val clientService: OAuth2AuthorizedClientService) {

    @GetMapping("/public")
    fun getPublicRoute(): String {
        return "This is a public route. No authentication required."
    }

    @GetMapping("/login")
    fun getPrivateRoute(response: HttpServletResponse): Any {
        var accessToken: String? = null
        var refreshToken: String? = null
        val authentication = SecurityContextHolder.getContext().authentication

        return if (authentication != null && authentication.isAuthenticated) {
            val oidcUser = authentication.principal as? OidcUser

            // Get the JWT Access Token
            val jwtToken = when (authentication) {
                is OAuth2AuthenticationToken -> {
                    val authorizedClient = clientService.loadAuthorizedClient<OAuth2AuthorizedClient>(
                        authentication.authorizedClientRegistrationId,
                        authentication.name
                    )
                    accessToken = authorizedClient?.accessToken?.tokenValue
                    refreshToken = authorizedClient?.refreshToken?.tokenValue
                }
                else -> null
            }

            // Get the ID Token
            val idToken = oidcUser?.idToken?.tokenValue

            val userInfoWithTokens = UserInfoWithTokens(
                userInfo = UserInfo(
                    name = oidcUser?.fullName ?: authentication.name,
                    email = oidcUser?.email ?: "",
                    roles = authentication.authorities.map { it.authority },
                    claims = oidcUser?.claims?.filterKeys {
                        it in setOf("given_name", "family_name", "email_verified", "preferred_username")
                    } ?: emptyMap()
                ),
                accessToken = accessToken,
                refreshToken = refreshToken,
                idToken = idToken
            )
            println("Access Token " + accessToken)
            println("Refresh Token " + refreshToken)
            println("ID Token " + idToken)
           if(userInfoWithTokens.idToken != null && userInfoWithTokens.accessToken != null) {

                ResponseEntity.status(HttpStatus.FOUND).body(response.setHeader("Location", "http://localhost:8081/api/verify-token"))
            } else {
                ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build()
            }
        } else {
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        }
    }

    @GetMapping("/logout")
    fun logout(request: HttpServletRequest, response: HttpServletResponse): ResponseEntity<Void> {
        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication != null && authentication.isAuthenticated) {
            SecurityContextHolder.clearContext()
            request.session.invalidate()

            // Redirect to Keycloak logout with redirect_uri parameter to go back to login
            val keycloakLogoutUrl = "http://localhost:8080/realms/springboot-realm/protocol/openid-connect/logout"

            response.setHeader("Location", keycloakLogoutUrl)
            return ResponseEntity.status(HttpStatus.FOUND).build()
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
    }

    @GetMapping("/verify-token")
    fun verifyToken(): ResponseEntity<String> {
        val authentication = SecurityContextHolder.getContext().authentication
        return if (authentication != null && authentication.isAuthenticated) {
            ResponseEntity.ok("Token is valid")
        } else {
            ResponseEntity.status(401).build()
        }
    }


}