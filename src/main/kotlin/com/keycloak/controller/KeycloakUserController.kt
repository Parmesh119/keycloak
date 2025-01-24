package com.keycloak.controller

import com.keycloak.model.UserDTO
import com.keycloak.model.UserInfo
import com.keycloak.model.UserInfoWithTokens
import com.keycloak.model.UserUpdateDTO
import com.keycloak.service.EmailService
import com.keycloak.service.KeycloakAdminService
import jakarta.servlet.RequestDispatcher
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.UserRepresentation
import org.springframework.http.*
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
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
    private val keycloakAdminService: KeycloakAdminService,
    private val emailService: EmailService
) {

    private val keycloakBaseUrl = "http://localhost:8080/realms/master/protocol/openid-connect"
    private val adminBaseUrl = "http://localhost:8080/admin/realms/master"
    private val clientId = "config"
    private val clientSecret = "sDoL4iAzeYquc7mtoubGr5t1F8yDRif4"
    private val tokenEndpoint = "$keycloakBaseUrl/token"

    @GetMapping("/public")
    fun getPublicRoute(): String {
        return "This is a public route. No authentication required."
    }

    @GetMapping("/login")
    fun getPrivateRoute(response: HttpServletResponse): ResponseEntity<Any> {
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
            return ResponseEntity.ok(userInfoWithTokens)
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

    @GetMapping("/error")
    fun handleError(request: HttpServletRequest): ResponseEntity<Any> {
        val status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE) as? Int
        return when (status) {
            404 -> ResponseEntity.notFound().build()
            403 -> ResponseEntity.status(HttpStatus.FORBIDDEN).build()
            500 -> ResponseEntity.internalServerError().build()
            else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
    }

    // Fetch all users
    @GetMapping("/users/list")
    fun getAllUsers(): ResponseEntity<List<UserRepresentation>> {
        val token = getAdminAccessToken()
        val headers = createHeaders(token)
        // Create authentication token
        headers["Authorization"] = "Bearer $token"
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
    fun createUser(@RequestBody userDTO: UserDTO): ResponseEntity<out Any> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        val res = keycloakAdminService.createUser(userDTO, headers)

        val loginLink = "http://example.com/login"
        val emailBody = """
            Welcome to our app!
            
            Here are your login details:
            Email: ${userDTO.email}
            Password: ${userDTO.credentials?.first()?.value}
            
            Please log in within 12 hours: $loginLink
        """.trimIndent()
        userDTO.email?.let { emailService.sendEmail(it, "New Account Created", emailBody) }

        return res
    }

    // Update a user
    @PutMapping("/users/update")
    fun updateUser(@RequestBody UserUpdateDTO: UserUpdateDTO): ResponseEntity<out Any> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.updateUser(UserUpdateDTO, headers)
    }

    // Delete a user
    @DeleteMapping("/users/delete/{id}")
    fun deleteUser(@PathVariable id: String): ResponseEntity<String> {
        val token = getAdminAccessToken() // Get the admin access token
        val headers = createHeaders(token) // Create headers with the token
        return keycloakAdminService.deleteUser(id, headers)
    }

    @GetMapping("/admin")
    // Helper method to fetch admin access token
    fun getAdminAccessToken(): String {
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
        createHeaders(response.body?.get("access_token") as String)
        headers["Authorization"] = "Bearer $response"
        return response.body?.get("access_token") as? String
            ?: throw RuntimeException("Failed to fetch access token")
    }

    // Helper method to create HTTP headers with the access token
    private fun createHeaders(token: String): HttpHeaders {
        return HttpHeaders().apply {
            set("Authorization", "Bearer $token")
            contentType = MediaType.APPLICATION_JSON
        }
    }

    @GetMapping("/get-access")
    fun getAccessTokenFromOpenID(): ResponseEntity<String> {
        // Prepare form data
        val map: MultiValueMap<String, String> = LinkedMultiValueMap()
        map.add("grant_type", "client_credentials")
        map.add("client_id", "config")  // Replace with actual client_id
        map.add("scope", "openid")
        map.add("username", "parmesh")  // Replace with actual username
        map.add("password", "admin")   // Replace with actual password
        map.add("client_secret", "sDoL4iAzeYquc7mtoubGr5t1F8yDRif4")  // Replace with actual client_secret

        // Set headers
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED

        // Wrap data in HttpEntity
        val entity: HttpEntity<MultiValueMap<String, String>> = HttpEntity(map, headers)

        // Initialize RestTemplate
        val restTemplate = RestTemplate()

        // Send POST request to token endpoint
        val response = restTemplate.exchange(
            "http://localhost:8080/realms/master/protocol/openid-connect/token", // The token endpoint URL
            HttpMethod.POST,  // HTTP Method
            entity,  // Request entity with data and headers
            Map::class.java  // Response type
        )

        // Extract access_token from the response body
        val accessToken = (response.body?.get("access_token") as? String)
            ?: throw RuntimeException("Failed to fetch access token")

        println(accessToken)

        // Verify the token by calling /api/verify-token
        return ResponseEntity.ok(accessToken)
    }

    @GetMapping("/users/list/client")
    fun listClient(): List<ClientRepresentation> {
        val token = getAdminAccessToken()
        val headers = createHeaders(token)
        return keycloakAdminService.listClients(headers)
    }

    @GetMapping("/users/list/client/{id}")
    fun getClient(@PathVariable id: String): ClientRepresentation? {
        val token = getAdminAccessToken()
        val headers = createHeaders(token)
        return keycloakAdminService.getClientByClientId(headers, id)
    }
}