package com.keycloak.service

import com.keycloak.model.UserDTO
import org.keycloak.admin.client.Keycloak
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.UserRepresentation
import org.springframework.stereotype.Service
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus

@Service
class KeycloakAdminService(private val keycloak: Keycloak) {

    private val realm = "springboot-realm"

    fun createUser(userDTO: UserDTO): ResponseEntity<String> {
        try {
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

            val response = keycloak.realm(realm).users().create(user)
            return if (response.status == 201) {
                ResponseEntity.status(HttpStatus.CREATED).body("User created successfully")
            } else {
                ResponseEntity.status(response.status).body("Failed to create user")
            }
        } catch (e: Exception) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error creating user: ${e.message}")
        }
    }

    fun getAllUsers(): ResponseEntity<List<UserRepresentation>> {
        return try {
            val users = keycloak.realm(realm).users().list()
            ResponseEntity.ok(users)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build()
        }
    }

    fun updateUser(id: String, userDTO: UserDTO): ResponseEntity<String> {
        try {
            val user = keycloak.realm(realm).users().get(id).toRepresentation()
            user.email = userDTO.email
            user.firstName = userDTO.firstName
            user.lastName = userDTO.lastName
            user.isEnabled = userDTO.enabled

            keycloak.realm(realm).users().get(id).update(user)
            return ResponseEntity.ok("User updated successfully")
        } catch (e: Exception) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error updating user: ${e.message}")
        }
    }

    fun deleteUser(id: String): ResponseEntity<String> {
        return try {
            keycloak.realm(realm).users().get(id).remove()
            ResponseEntity.ok("User deleted successfully")
        } catch (e: Exception) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error deleting user: ${e.message}")
        }
    }

    fun getUser(id: String): ResponseEntity<UserRepresentation> {
        return try {
            val user = keycloak.realm(realm).users().get(id).toRepresentation()
            ResponseEntity.ok(user)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build()
        }
    }
}