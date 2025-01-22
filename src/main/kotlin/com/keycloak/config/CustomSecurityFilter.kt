package com.keycloak.config
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.JWTVerifier
import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import jakarta.servlet.*
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import java.io.IOException
import java.net.URL
import java.security.interfaces.RSAPublicKey

class CustomSecurityFilter : Filter {

    private val logger: Logger = LoggerFactory.getLogger(javaClass)
    private var jwkProvider: JwkProvider = JwkProviderBuilder(URL("http://localhost:8080/realms/master/protocol/openid-connect/certs")).build()

    @Throws(IOException::class, ServletException::class)
    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        try {
            val httpRequest = request as HttpServletRequest
            if (httpRequest.servletPath == "/api/verify-token") {
                val token = httpRequest.getParameter("access_token")
                    ?: httpRequest.getHeader("Authorization")?.substring(7)

                if (token != null) {
                    val decodedJWT = JWT.decode(token)

                    // Start verification process
                    val jwk: Jwk = jwkProvider.get(decodedJWT.keyId)

                    // Assuming all tokens are signed using RSA256 algorithm
                    val algorithm = Algorithm.RSA256(jwk.publicKey as RSAPublicKey, null)

                    val verifier: JWTVerifier = JWT.require(algorithm)
                        .withIssuer("http://localhost:8080/realms/master")
                        .withAudience("master-realm")
                        .build()
                    verifier.verify(decodedJWT)

                    SecurityContextHolder.getContext().authentication =
                        UsernamePasswordAuthenticationToken(decodedJWT.subject, null,
                            listOf(SimpleGrantedAuthority("SIMPLE_AUTHORITY")))
                    logger.info("User ${decodedJWT.subject} authenticated")
                } else {
                    logger.error("No token provided")
                }
            }
        } catch (jwtVerificationException: JWTVerificationException) {
            logger.error("JWT Verification Exception", jwtVerificationException)
        } catch (e: Exception) {
            logger.error("Exception", e)
        }

        chain.doFilter(request, response)
        SecurityContextHolder.clearContext()
    }
}

