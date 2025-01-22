package com.keycloak.model

data class UserDTO(
    val username: String,
    val email: String?,
    val firstName: String?,
    val lastName: String?,
    val enabled: Boolean = true,
    val credentials: List<CredentialDTO>? = null
)

data class UserUpdateDTO(
    val username: String?,
    val email: String?,
    val firstName: String?,
    val lastName: String?,
    val enabled: Boolean? = true,
    val credentials: List<CredentialDTO>? = null
)

data class CredentialDTO(
    val type: String = "1234",
    val value: String,
    val temporary: Boolean = false
)
