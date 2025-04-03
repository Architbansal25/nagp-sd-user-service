package com.nagp.secure.user.management.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final UserDetails userDetails;
    private final String token;

    public JwtAuthenticationToken(UserDetails userDetails, String token) {
        super(userDetails.getAuthorities());
        this.userDetails = userDetails;
        this.token = token;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return userDetails;
    }
}