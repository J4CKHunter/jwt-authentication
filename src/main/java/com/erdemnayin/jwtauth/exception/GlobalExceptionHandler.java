package com.erdemnayin.jwtauth.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(GenericException.class)
    public ResponseEntity<?> genericException(GenericException e){
        Map<String, String> errors = new HashMap<>();
        errors.put("error", e.getMessage());

        return ResponseEntity
                .status(e.getHttpStatus())
                .body(errors);
    }
}
