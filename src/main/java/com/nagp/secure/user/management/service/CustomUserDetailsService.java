package com.nagp.secure.user.management.service;

import com.nagp.secure.user.management.model.User;
import com.nagp.secure.user.management.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Implement logic to fetch user from database
        User user = userRepository.findByEmail(email).orElse(null);
        if (user!=null) {
            return org.springframework.security.core.userdetails.User.builder().username(user.getEmail()).
                    password(user.getPassword()).roles(user.getRole().toString()).build();
        } else {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
