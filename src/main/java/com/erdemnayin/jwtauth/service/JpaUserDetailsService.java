package com.erdemnayin.jwtauth.service;

import com.erdemnayin.jwtauth.exception.GenericException;
import com.erdemnayin.jwtauth.model.SecurityUser;
import com.erdemnayin.jwtauth.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*TODO: security config'de http.userDetailsService'e geçilecek bu class*/
@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public JpaUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        SecurityUser securityUser = userRepository.findByUsername(username).map(SecurityUser::new).get();
        System.out.println(securityUser);

        return userRepository
                .findByUsername(username)
                .map(SecurityUser::new)
                .orElseThrow(() -> new GenericException("User not found: " + username, HttpStatus.NOT_FOUND));
    }
}
