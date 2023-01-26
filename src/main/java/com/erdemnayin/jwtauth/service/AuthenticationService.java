package com.erdemnayin.jwtauth.service;

import com.erdemnayin.jwtauth.dto.TokenResponseDto;
import com.erdemnayin.jwtauth.dto.UserResponseDto;
import com.erdemnayin.jwtauth.dto.request.LoginRequest;
import com.erdemnayin.jwtauth.exception.GenericException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;

    private final UserService userService;

    private final TokenService tokenService;

    public AuthenticationService(AuthenticationManager authenticationManager,
                                 UserService userService,
                                 TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.tokenService = tokenService;
    }

    public TokenResponseDto login(LoginRequest loginRequest){
        try{
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            return TokenResponseDto.builder()
                    .jwt(tokenService.generateTokenWithScope(authentication))
//                    .jwt(tokenService.generateTokenWithAuthorities(authentication))
                    .user(userService.getUser(loginRequest.getUsername()))
                    .build();
        }catch (final BadCredentialsException badCredentialsException){
            throw new GenericException("Invalid username or password", HttpStatus.BAD_REQUEST);
        }
    }

    public UserResponseDto getAuthenticatedUser(){
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userService.getUser(username);
    }

}
