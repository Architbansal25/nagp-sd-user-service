package com.nagp.secure.user.management.service;

import com.nagp.secure.user.management.model.Role;
import com.nagp.secure.user.management.model.User;
import com.nagp.secure.user.management.repository.UserRepository;
import com.nagp.secure.user.management.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public User registerUser(User user) {
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        return userRepository.save(user);
    }
    public List<User> getAllUsers(){
        return userRepository.findAll();
    }

    public Optional<User> authenticate(User reqUser) {

        return userRepository.findByEmail(reqUser.getEmail())
                .filter(user -> passwordEncoder.matches(reqUser.getPassword(), user.getPassword()));
    }
    public String getAcessToken(String email){
        User user = userRepository.findByEmail(email).orElse(null);
        assert user != null;
        return jwtUtil.generateToken(user);
    }
}
