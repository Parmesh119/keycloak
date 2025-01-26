package com.keycloak.model

data class UserDTO(
    val username: String,
    val email: String?,
    val firstName: String?,
    val lastName: String?,
    val enabled: Boolean? = true,
    val emailVerified: Boolean? = true,
    val requiredActions: List<String>? = null,
    val serviceAccountClientId: String? = null,
    val credentials: List<CredentialDTO>? = null,
    val groups: List<String>? = null,
    val clientRoles: Map<String, List<String>>? = null,
    val attributes: List<AttributeDTO>? = null,
)

data class AttributeDTO(
    val required: RequiredRolesDTO?
)

data class RequiredRolesDTO(
    val roles: List<String>?
)

data class UserUpdateDTO(
    val id: String,
    val username: String?,
    val email: String?,
    val firstName: String?,
    val lastName: String?,
    val enabled: Boolean? = true,
    val emailVerified: Boolean? = true,
    val requiredActions: List<String>? = null,
    val serviceAccountClientId: String? = null,
    val credentials: List<CredentialDTO>? = null,
    val groups: List<String>? = null,
    val clientRoles: Map<String, List<String>>? = null,
    val attributes: List<AttributeDTO>? = null,
)

data class CredentialDTO(
    val type: String = "1234",
    val value: String,
    val temporary: Boolean = false
)

data class ClientRepresentation(
    val id: String,
    val clientId: String,
    val name: String? = null,
    val description: String? = null,
    val enabled: Boolean? = null
)