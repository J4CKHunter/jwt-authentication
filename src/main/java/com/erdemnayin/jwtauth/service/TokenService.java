package com.erdemnayin.jwtauth.service;

import com.nimbusds.jose.JWSHeader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class TokenService {

    @Value("${jwt-variable.EXPIRES_AMOUNT_TO_ADD}")
    private Integer EXPIRES_AMOUNT_TO_ADD;

    private final JwtEncoder jwtEncoder;

    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public Jwt generateTokenWithScope(Authentication authentication){
        Instant now = Instant.now();

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        System.out.println("Scope: " + scope);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://erdemnayin.com")
                .audience(List.of("erdem"))
                .issuedAt(now)
                .expiresAt(now.plus(EXPIRES_AMOUNT_TO_ADD, ChronoUnit.SECONDS))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();


//        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims));
    }

    public Jwt generateTokenWithAuthorities(Authentication authentication){
        Instant now = Instant.now();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        System.out.println("Authorities: " + authorities);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://erdemnayin.com")
                .issuedAt(now)
                .expiresAt(now.plus(EXPIRES_AMOUNT_TO_ADD, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("authorities", authorities)
                .build();

//        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims));
    }
}
