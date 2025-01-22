package com.keycloak.service

import com.keycloak.model.UserDTO
import com.keycloak.model.UserUpdateDTO
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.UserRepresentation
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.*
import org.springframework.stereotype.Service
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestTemplate

@Service
class KeycloakAdminService(private val restTemplate: RestTemplate) {

    private val realm = "master"
    private val adminBaseUrl = "http://localhost:8080/admin/realms/master"

    // Create a user
    fun createUser(userDTO: UserDTO, headers: HttpHeaders): ResponseEntity<String> {
        val user = UserRepresentation().apply {
            username = userDTO.username
            email = userDTO.email
            firstName = userDTO.firstName
            lastName = userDTO.lastName
            isEnabled = userDTO.enabled

            if (userDTO.credentials != null) {
                credentials = userDTO.credentials.map { cred ->
                    CredentialRepresentation().apply {
                        type = cred.type
                        value = cred.value
                        isTemporary = cred.temporary
                    }
                }
            }
        }

        val request = org.springframework.http.HttpEntity(user, headers)
        val response = restTemplate.postForEntity("$adminBaseUrl/users", request, String::class.java)

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.status(201).body("User created successfully")
        } else {
            ResponseEntity.status(response.statusCode).body("Failed to create user")
        }
    }

    // Fetch all users
    fun getAllUsers(headers: HttpHeaders): ResponseEntity<List<UserRepresentation>> {
        val request = org.springframework.http.HttpEntity(null, headers)
        val response = restTemplate.exchange("$adminBaseUrl/users", org.springframework.http.HttpMethod.GET, request, Array<UserRepresentation>::class.java)

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.ok(response.body?.toList())
        } else {
            ResponseEntity.status(response.statusCode).build()
        }
    }

    // Get user by ID
    fun getUser(id: String, headers: HttpHeaders): ResponseEntity<UserRepresentation> {
        val request = org.springframework.http.HttpEntity(null, headers)
        val response = restTemplate.exchange("$adminBaseUrl/users/$id", org.springframework.http.HttpMethod.GET, request, UserRepresentation::class.java)

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.ok(response.body)
        } else {
            ResponseEntity.status(response.statusCode).build()
        }
    }

    // Update a user
    fun updateUser(id: String, userUpdateDTO: UserUpdateDTO, headers: HttpHeaders): ResponseEntity<String> {
        val user = UserRepresentation().apply {
            username = userUpdateDTO.username
            email = userUpdateDTO.email
            firstName = userUpdateDTO.firstName
            lastName = userUpdateDTO.lastName
            isEnabled = userUpdateDTO.enabled

            if (userUpdateDTO.credentials != null) {
                credentials = userUpdateDTO.credentials.map { cred ->
                    CredentialRepresentation().apply {
                        type = cred.type
                        value = cred.value
                        isTemporary = cred.temporary
                    }
                }
            }
        }

        val request = org.springframework.http.HttpEntity(user, headers)
        val response = restTemplate.exchange("$adminBaseUrl/users/$id", org.springframework.http.HttpMethod.PUT, request, String::class.java)

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.ok("User updated successfully")
        } else {
            ResponseEntity.status(response.statusCode).body("Failed to update user")
        }
    }

    // Delete a user
    fun deleteUser(id: String, headers: HttpHeaders): ResponseEntity<String> {
        val request = org.springframework.http.HttpEntity(null, headers)
        val response = restTemplate.exchange("$adminBaseUrl/users/$id", org.springframework.http.HttpMethod.DELETE, request, String::class.java)

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.ok("User deleted successfully")
        } else {
            ResponseEntity.status(response.statusCode).body("Failed to delete user")
        }
    }

    fun sendPostRequest() {
        // Prepare form data
        val map: MultiValueMap<String, String> = LinkedMultiValueMap()
        map.add("key1", "value1")
        map.add("key2", "value2")

        // Set headers
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED

        // Wrap data in HttpEntity
        val entity: HttpEntity<MultiValueMap<String, String>> = HttpEntity(map, headers)

        // Send POST request
        val response = restTemplate.exchange(
            "your-endpoint-url",  // Replace with the actual URL
            HttpMethod.POST,  // HTTP Method
            entity,  // Request entity with data and headers
            String::class.java // Response type
        )

        // Handle the response
        println(response.body)
    }
}
