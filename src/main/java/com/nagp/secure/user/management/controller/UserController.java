package com.nagp.secure.user.management.controller;

import com.nagp.secure.user.management.model.User;
import com.nagp.secure.user.management.service.UserService;
import com.nagp.secure.user.management.utils.JwtUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;


@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        User savedUser = userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Set<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        if(roles.contains("ROLE_ADMIN")){
            return ResponseEntity.ok(userService.getAllUsers());
        }
        else {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid Role"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        Optional<User> authenticatedUser = userService.authenticate(user);

        return authenticatedUser
                .map(u -> ResponseEntity.ok(Map.of(
                        "token", userService.getAcessToken(user.getEmail())
                )))
                .orElseGet(() -> ResponseEntity.status(401).body(Map.of("error", "Invalid credentials")));
    }
}

