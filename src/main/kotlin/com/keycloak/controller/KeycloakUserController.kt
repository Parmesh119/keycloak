package com.keycloak.controller

import com.keycloak.model.UserDTO
import com.keycloak.model.UserInfo
import com.keycloak.model.UserInfoWithTokens
import com.keycloak.model.UserUpdateDTO
import com.keycloak.service.KeycloakAdminService
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.keycloak.representations.idm.UserRepresentation
import org.springframework.http.*
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.RestTemplate
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap


@RestController
@RequestMapping("/api")
class KeycloakUserController(
    private val clientService: OAuth2AuthorizedClientService,
    private val restTemplate: RestTemplate,
    private val keycloakAdminService: KeycloakAdminService
) {

    private val keycloakBaseUrl = "http://localhost:8080/realms/master/protocol/openid-connect"
    private val adminBaseUrl = "http://localhost:8080/admin/realms/master"
    private val clientId = "admin-cli"
    private val clientSecret = "rUogbpqrIRteo6HnMH0gEY7usc4q3PC0"
    private val tokenEndpoint = "$keycloakBaseUrl/token"

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
            if (userInfoWithTokens.idToken != null && userInfoWithTokens.accessToken != null) {
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
            val keycloakLogoutUrl = "http://localhost:8080/realms/master/protocol/openid-connect/logout"

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

    // Fetch all users
    @GetMapping("/users")
    fun getAllUsers(): ResponseEntity<List<UserRepresentation>> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.getAllUsers(headers)
    }

    // Get user by ID
    @GetMapping("/users/{id}")
    fun getUser(@PathVariable id: String): ResponseEntity<UserRepresentation> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.getUser(id, headers)
    }

    // Create a user
    @PostMapping("/users/create")
    fun createUser(@RequestBody userDTO: UserDTO): ResponseEntity<String> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.createUser(userDTO, headers)
    }

    // Update a user
    @PutMapping("/users/update/{id}")
    fun updateUser(@PathVariable id: String, @RequestBody UserUpdateDTO: UserUpdateDTO): ResponseEntity<String> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.updateUser(id, UserUpdateDTO, headers)
    }

    // Delete a user
    @DeleteMapping("/users/delete/{id}")
    fun deleteUser(@PathVariable id: String): ResponseEntity<String> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.deleteUser(id, headers)
    }

    // Helper method to fetch admin access token
    private fun getAdminAccessToken(): String {
        // Prepare form data
        val map: MultiValueMap<String, String> = LinkedMultiValueMap()
        map.add("grant_type", "client_credentials")
        map.add("client_id", clientId)
        map.add("client_secret", clientSecret)

        // Set headers
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        // Wrap data in HttpEntity
        val entity: HttpEntity<MultiValueMap<String, String>> = HttpEntity(map, headers)

        // Send POST request
        val response = restTemplate.exchange(
            tokenEndpoint,  // Replace with the actual URL
            HttpMethod.POST,  // HTTP Method
            entity,  // Request entity with data and headers
            Map::class.java
        )
        return (response.body?.get("access_token") as? String)
            ?: throw RuntimeException("Failed to fetch access token")
    }

    // Helper method to create HTTP headers with the access token
    private fun createHeaders(token: String): HttpHeaders {
        return HttpHeaders().apply {
            set("Authorization", "Bearer $token")
            contentType = MediaType.APPLICATION_JSON
        }
    }
}