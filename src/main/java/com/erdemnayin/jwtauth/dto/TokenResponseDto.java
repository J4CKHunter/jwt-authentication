package com.erdemnayin.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class TokenResponseDto {
    private Jwt jwt;
    private UserResponseDto user;
}
