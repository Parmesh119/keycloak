package com.keycloak.service

import com.keycloak.model.UserDTO
import com.keycloak.model.UserUpdateDTO
import org.keycloak.representations.idm.*
import org.springframework.core.ParameterizedTypeReference
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
    fun createUser(userDTO: UserDTO, headers: HttpHeaders): ResponseEntity<out Any> {
        try {
            // Create the user representation object
            val user = UserRepresentation().apply {
                username = userDTO.username
                email = userDTO.email
                firstName = userDTO.firstName
                lastName = userDTO.lastName
                isEnabled = userDTO.enabled
                isEmailVerified = userDTO.emailVerified

                // If required actions are provided, add them
                if (userDTO.requiredActions != null) {
                    requiredActions = userDTO.requiredActions
                }

                // If credentials are provided, map them
                if (userDTO.credentials != null) {
                    credentials = userDTO.credentials.map { cred ->
                        CredentialRepresentation().apply {
                            type = cred.type
                            value = cred.value
                            isTemporary = cred.temporary
                        }
                    }
                }

                if (userDTO.attributes != null) {
                    for (attribute in userDTO.attributes) {
                        val requiredRoles = attribute.required?.roles
                        if (requiredRoles != null && requiredRoles.isNotEmpty()) {
                            // Do something with the roles, like logging or processing
                            println("Required roles: $requiredRoles")
                        }
                    }
                }

            }


            // Prepare the request with user data and headers
            val request = org.springframework.http.HttpEntity(user, headers)
            val response = restTemplate.postForEntity("$adminBaseUrl/users", request, String::class.java)


            // Extract the userId from the response
            val userId = extractUserId(response)
            // Fetch the JWT token to use for authorization

            val clientid = getClientByClientId(headers, userDTO.serviceAccountClientId ?: "config")?.id
                ?: throw RuntimeException("Client not found")
            // Step 2: Assign client roles
            userDTO.clientRoles?.forEach { (clientId, roles) ->
                // Fetch the role details by name and pass the Bearer token in the request
                val roleMappings = roles.map { roleName ->
                    val roleResponse = restTemplate.exchange(
                        "$adminBaseUrl/clients/$clientid/roles/$roleName",
                        HttpMethod.GET,
                        HttpEntity<Void>(headers),  // Use the headers_bearer here
                        RoleRepresentation::class.java
                    )
                    roleResponse.body ?: throw RuntimeException("Role $roleName not found for client $clientId")
                }

                // Prepare the request for role mappings and pass the Bearer token
                val roleRequest = HttpEntity(roleMappings, headers)  // Use headers_bearer here
                restTemplate.postForEntity(
                    "$adminBaseUrl/users/$userId/role-mappings/clients/$clientid",
                    roleRequest,
                    String::class.java
                )
            }


            // Step 3: Assign groups
            userDTO.groups?.forEach { groupName ->
                // Fetch the group details by name
                val groupResponse = restTemplate.getForEntity(
                    "$adminBaseUrl/groups?search=$groupName",
                    Array<GroupRepresentation>::class.java
                )

                // Get the first group from the response
                val group = groupResponse.body?.firstOrNull() ?: createOrGetGroup(groupName)

                // Assign the group to the user with the Bearer token
                restTemplate.put(
                    "$adminBaseUrl/users/$userId/groups/${group.id}",
                    HttpEntity(null, headers)  // Use headers_bearer here
                )
            }

            return if (response.statusCode.is2xxSuccessful) {
                ResponseEntity.status(201).body(getUser(response.headers.location!!.path.split("/").last(), headers))
            } else {
                ResponseEntity.status(response.statusCode).body("Failed to create user")
            }
        } catch (e: Exception) {
            // Handle exceptions and return error response
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to create user: ${e.message}")
        }
    }

    fun getClientByClientId(headers: HttpHeaders, clientId: String): ClientRepresentation? {
        val restTemplate = RestTemplate()
        val adminBaseUrl = "http://localhost:8080/admin/realms/master"

        val responseEntity = restTemplate.exchange(
            "$adminBaseUrl/clients?clientId=$clientId",
            HttpMethod.GET,
            HttpEntity<Void>(headers),
            Array<ClientRepresentation>::class.java
        )

        return responseEntity.body?.firstOrNull()
    }

    fun getAdminAccessToken(): String {
        // Prepare form data
        val map: MultiValueMap<String, String> = LinkedMultiValueMap()
        map.add("grant_type", "client_credentials")
        map.add("client_id", "config")
        map.add("client_secret", "sDoL4iAzeYquc7mtoubGr5t1F8yDRif4")

        // Set headers
        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        // Wrap data in HttpEntity
        val entity: HttpEntity<MultiValueMap<String, String>> = HttpEntity(map, headers)

        // Send POST request
        val response = restTemplate.exchange(
            "http://localhost:8080/realms/master/protocol/openid-connect/token",  // Replace with the actual URL
            HttpMethod.POST,  // HTTP Method
            entity,  // Request entity with data and headers
            Map::class.java
        )
        return response.body?.get("access_token") as? String
            ?: throw RuntimeException("Failed to fetch access token")
    }


    fun extractUserId(response: ResponseEntity<String>): String {
        // Logic to extract userId from the response, e.g., parsing the URL or response body
        return response.headers.location?.path?.split("/")?.last()
            ?: throw RuntimeException("User ID extraction failed")
    }


    // Fetch all users
    fun getAllUsers(headers: HttpHeaders): ResponseEntity<List<UserRepresentation>> {
        val request = org.springframework.http.HttpEntity(null, headers)
        val response = restTemplate.exchange(
            "$adminBaseUrl/users",
            org.springframework.http.HttpMethod.GET,
            request,
            object : ParameterizedTypeReference<List<UserRepresentation>>() {})

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.ok(response.body?.toList())
        } else {
            ResponseEntity.status(response.statusCode).build()
        }
    }

    // Get user by ID
    fun getUser(id: String, headers: HttpHeaders): ResponseEntity<UserRepresentation> {
        val request = org.springframework.http.HttpEntity(null, headers)
        val response = restTemplate.exchange(
            "$adminBaseUrl/users/$id",
            org.springframework.http.HttpMethod.GET,
            request,
            UserRepresentation::class.java
        )

        return if (response.statusCode.is2xxSuccessful) {
            ResponseEntity.ok(response.body)
        } else {
            ResponseEntity.status(response.statusCode).build()
        }
    }

    // Update a user
    fun updateUser(userUpdateDTO: UserUpdateDTO, headers: HttpHeaders): ResponseEntity<String> {

        try {
            val existingUser = getUser(userUpdateDTO.id, headers)
            if (existingUser.statusCode != HttpStatus.OK) {
                return ResponseEntity.status(existingUser.statusCode).body("User not found")
            }

            val user = UserRepresentation().apply {
                username = userUpdateDTO.username
                email = userUpdateDTO.email
                firstName = userUpdateDTO.firstName
                lastName = userUpdateDTO.lastName
                isEnabled = userUpdateDTO.enabled
                isEmailVerified = userUpdateDTO.emailVerified

                if (userUpdateDTO.requiredActions != null) {
                    requiredActions = userUpdateDTO.requiredActions
                }

                if (userUpdateDTO.credentials != null) {
                    credentials = userUpdateDTO.credentials.map { cred ->
                        CredentialRepresentation().apply {
                            type = cred.type
                            value = cred.value
                            isTemporary = cred.temporary
                        }
                    }
                }

                if (userUpdateDTO.attributes != null) {
                    for (attribute in userUpdateDTO.attributes) {
                        val requiredRoles = attribute.required?.roles
                        if (requiredRoles != null && requiredRoles.isNotEmpty()) {
                            println("Required roles: $requiredRoles")
                        }
                    }
                }
            }

            val id = userUpdateDTO.id
            val request = org.springframework.http.HttpEntity(user, headers)
            val response = restTemplate.exchange(
                "$adminBaseUrl/users/$id",
                org.springframework.http.HttpMethod.PUT,
                request,
                String::class.java
            )

            val clientid = getClientByClientId(headers, userUpdateDTO.serviceAccountClientId ?: "config")?.id
                ?: throw RuntimeException("Client not found")

            userUpdateDTO.clientRoles?.forEach { (_, roles) ->
                // Get existing client roles for the user
                val existingRoleMappings = restTemplate.exchange(
                    "$adminBaseUrl/users/$id/role-mappings/clients/$clientid",
                    HttpMethod.GET,
                    HttpEntity<Void>(headers),
                    Array<RoleRepresentation>::class.java
                )

                // Filter out roles to remove
                val rolesToRemove = existingRoleMappings.body
                    ?.filter { existingRole ->
                        existingRole.name !in roles
                    } ?: emptyList()

                // Remove existing roles not in the new role set
                if (rolesToRemove.isNotEmpty()) {
                    val removeRoleRequest = HttpEntity(rolesToRemove, headers)
                    restTemplate.exchange(
                        "$adminBaseUrl/users/$id/role-mappings/clients/$clientid",
                        HttpMethod.DELETE,
                        removeRoleRequest,
                        Void::class.java
                    )
                }

                // Add new roles
                val roleMappings = roles.map { roleName ->
                    val roleResponse = restTemplate.exchange(
                        "$adminBaseUrl/clients/$clientid/roles/$roleName",
                        HttpMethod.GET,
                        HttpEntity<Void>(headers),
                        RoleRepresentation::class.java
                    )
                    roleResponse.body ?: throw RuntimeException("Role $roleName not found")
                }

                // Add new roles
                val roleRequest = HttpEntity(roleMappings, headers)
                restTemplate.postForEntity(
                    "$adminBaseUrl/users/$id/role-mappings/clients/$clientid",
                    roleRequest,
                    String::class.java
                )
            }

            userUpdateDTO.groups?.forEach { groupName ->
                val groupResponse = restTemplate.exchange(
                    "$adminBaseUrl/groups?search=$groupName",
                    HttpMethod.GET,
                    HttpEntity<Void>(headers),
                    Array<GroupRepresentation>::class.java
                )

                val group = groupResponse.body?.firstOrNull() ?: createOrGetGroup(groupName)

                restTemplate.put(
                    "$adminBaseUrl/users/$id/groups/${group.id}",
                    HttpEntity(null, headers)
                )
            }

            return if (response.statusCode.is2xxSuccessful) {
                ResponseEntity.ok("User updated successfully")
            } else {
                ResponseEntity.status(response.statusCode).body("Failed to update user")
            }
        } catch (e: Exception) {
            throw e
        }
    }

    fun createOrGetGroup(groupName: String): GroupRepresentation {
        val admin_token = getAdminAccessToken()
        val headers = HttpHeaders().apply {
            setBearerAuth(admin_token)
            contentType = MediaType.APPLICATION_JSON
        }

        // First, try to find the group
        val existingGroupResponse = restTemplate.exchange(
            "$adminBaseUrl/groups?search=$groupName",
            HttpMethod.GET,
            HttpEntity<Void>(headers),
            Array<GroupRepresentation>::class.java
        )

        // If group exists, return the first match
        existingGroupResponse.body?.firstOrNull()?.let { return it }

        // If group doesn't exist, create a new group
        val newGroup = GroupRepresentation().apply {
            name = groupName
            path = "/$groupName"
        }

        val createGroupRequest = HttpEntity(newGroup, headers)
        restTemplate.postForEntity(
            "$adminBaseUrl/groups",
            createGroupRequest,
            Void::class.java
        )

        // Fetch and return the newly created group
        val createdGroupResponse = restTemplate.exchange(
            "$adminBaseUrl/groups?search=$groupName",
            HttpMethod.GET,
            HttpEntity<Void>(headers),
            Array<GroupRepresentation>::class.java
        )

        return createdGroupResponse.body?.firstOrNull()
            ?: throw RuntimeException("Failed to create or retrieve group: $groupName")
    }
    // Delete a user
    fun deleteUser(id: String, headers: HttpHeaders): ResponseEntity<String> {
        val request = org.springframework.http.HttpEntity(null, headers)
        val response = restTemplate.exchange(
            "$adminBaseUrl/users/$id",
            org.springframework.http.HttpMethod.DELETE,
            request,
            String::class.java
        )

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


    fun listClients(headers: HttpHeaders): List<ClientRepresentation> {
        val restTemplate = RestTemplate()
        val adminBaseUrl = "http://localhost:8080/admin/realms/master"

        val responseEntity = restTemplate.exchange(
            "$adminBaseUrl/clients",
            HttpMethod.GET,
            HttpEntity<Void>(headers),
            Array<ClientRepresentation>::class.java
        )

        return responseEntity.body?.toList() ?: emptyList()
    }
}
