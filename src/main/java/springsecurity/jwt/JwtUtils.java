package springsecurity.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    // Method to extract the JWT token from the HTTP request header
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");  // Get Authorization header
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {  // Check if the token starts with "Bearer "
            return bearerToken.substring(7);  // Return the token without the "Bearer " prefix
        }
        return null;  // Return null if the token is not found or is incorrectly formatted
    }

    // Method to generate a JWT token based on the username from UserDetails
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)  // Set the subject (username)
                .issuedAt(new Date())  // Set the issue date as the current date
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))  // Set expiration date
                .signWith(key())  // Sign the token with the secret key
                .compact();  // Return the compact, serialized JWT
    }

    // Method to extract the username from a JWT token
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())  // Verify the token using the secret key
                .build().parseSignedClaims(token)  // Parse the token and get claims
                .getPayload().getSubject();  // Extract and return the username from the payload
    }

    // Method to generate a SecretKey using the JWT secret from application properties
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));  // Decode the base64-encoded jwtSecret and generate a key
    }

    // Method to validate a JWT token by parsing it and checking for errors
    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key())  // Verify the token using the secret key
                    .build().parseSignedClaims(authToken);  // Parse the token to check if it's valid
            return true;  // Return true if the token is valid
        } catch (MalformedJwtException e) {  // Catch invalid JWT structure
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {  // Catch expired token error
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {  // Catch unsupported JWT error
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {  // Catch empty token error
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;  // Return false if the token is invalid or any exception occurs
    }
}
