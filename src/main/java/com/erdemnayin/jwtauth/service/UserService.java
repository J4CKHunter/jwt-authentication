package com.erdemnayin.jwtauth.service;

import com.erdemnayin.jwtauth.dto.UserResponseDto;
import com.erdemnayin.jwtauth.exception.GenericException;
import com.erdemnayin.jwtauth.model.User;
import com.erdemnayin.jwtauth.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findUserByUsername(String username){
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new GenericException("User not found: " + username, HttpStatus.NOT_FOUND));
    }

    public UserResponseDto getUser(String username){

        var user = findUserByUsername(username);

        return UserResponseDto.builder()
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }
}
