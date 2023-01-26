package com.erdemnayin.jwtauth.controller;

import com.erdemnayin.jwtauth.dto.UserResponseDto;
import com.erdemnayin.jwtauth.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HomeController {

    private final AuthenticationService authenticationService;

    public HomeController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("/public")
    public String publicEndpoint(){
        return "public endpoint called";
    }

    @GetMapping("/user")
    public String userEndpoint(){
        return "user endpoint called";
    }

    @GetMapping("/admin")
    public String adminEndpoint(){
        return "admin endpoint called";
    }

    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    @GetMapping("/admin-pre-authorize-scope")
    public String adminPreAuthorizeScope(){
        return "admin pre-authorize with scope endpoint is called";
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/admin-pre-authorize-role")
    public String adminPreAuthorizeRole(){
        return "admin pre-authorize with role endpoint is called";
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> meEndpoint(){
        return ResponseEntity.ok(authenticationService.getAuthenticatedUser());
    }
}
