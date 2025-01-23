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
import jakarta.servlet.http.HttpServletResponse
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
            if (httpRequest.servletPath == "/api/verify-token" ) {
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
                        .withAudience("master-realm") // Enforce the audience claim
                        .build()

                    // Verify the token
                    val verifiedJWT = verifier.verify(decodedJWT)

                    // Set authentication if the token is valid
                    SecurityContextHolder.getContext().authentication =
                        UsernamePasswordAuthenticationToken(
                            verifiedJWT.subject, null,
                            listOf(SimpleGrantedAuthority("SIMPLE_AUTHORITY"))
                        )

                    logger.info("User ${verifiedJWT.subject} authenticated successfully")
                } else {
                    logger.error("No token provided")
                    (response as HttpServletResponse).status = HttpServletResponse.SC_UNAUTHORIZED
                    response.writer.write("Unauthorized: No token provided")
                    return
                }
            }
        } catch (e: JWTVerificationException) {
            logger.error("JWT Verification Exception: ${e.message}")
            (response as HttpServletResponse).status = HttpServletResponse.SC_UNAUTHORIZED
            response.writer.write("Unauthorized: Invalid token")
            return
        } catch (e: Exception) {
            logger.error("Exception occurred: ${e.message}")
            (response as HttpServletResponse).status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR
            response.writer.write("Internal Server Error")
            return
        }

        chain.doFilter(request, response)
        SecurityContextHolder.clearContext()
    }
}


