package com.keycloak
data class UserInfo(
    val name: String,
    val email: String,
    val roles: List<String>,
    val claims: Map<String, Any>
)

data class UserInfoWithTokens(
    val userInfo: UserInfo,
    val accessToken: String?,
    val refreshToken: String?,
    val idToken: String?
)