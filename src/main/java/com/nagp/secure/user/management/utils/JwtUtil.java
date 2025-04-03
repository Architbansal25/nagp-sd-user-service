package com.nagp.secure.user.management.utils;
import java.security.Key;
import java.util.Date;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.nagp.secure.user.management.model.Role;
import com.nagp.secure.user.management.model.User;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;


@Component
public class JwtUtil {

    @Value("${jwt.hmac.secret}")
    private String secretKey;
    private Algorithm algorithm;
    private JWTVerifier verifier;

    @PostConstruct
    public void init() {
        algorithm = Algorithm.HMAC256(secretKey);
        verifier = JWT.require(algorithm).build();
    }
    public String generateToken( User user) {
        String email = user.getEmail();
        Role role = user.getRole();
        // 10 minutes in milliseconds
        long EXPIRATION_TIME = 10 * 60 * 1000;
        return JWT.create()
                .withSubject(email)
                .withClaim("role", role.name()) // Include role in JWT payload
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(algorithm);
    }

    public String extractEmail(String token) {
        return verifyToken(token).getSubject();
    }

    public String extractRole(String token) {
        return verifyToken(token).getClaim("role").asString();
    }
    public boolean validateToken(String token) {
        try {
            verifyToken(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    private DecodedJWT verifyToken(String token) {
        return verifier.verify(token);
    }
}
