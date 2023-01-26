package com.erdemnayin.jwtauth.config;

import com.erdemnayin.jwtauth.model.Role;
import com.erdemnayin.jwtauth.model.User;
import com.erdemnayin.jwtauth.repository.UserRepository;
import com.erdemnayin.jwtauth.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class StartupConfig implements CommandLineRunner {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public StartupConfig(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        userRepository.save(new User(null, "user", passwordEncoder.encode("password"), Role.USER));
        userRepository.save(new User(null, "admin", passwordEncoder.encode("password"), Role.ADMIN));

    }
}
