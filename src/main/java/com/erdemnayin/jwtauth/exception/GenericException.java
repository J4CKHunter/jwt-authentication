package com.erdemnayin.jwtauth.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

@Data
@EqualsAndHashCode(callSuper = true)
public class GenericException extends RuntimeException{
    private final String message;
    private final HttpStatus httpStatus;


    public GenericException(String message, HttpStatus httpStatus) {
        this.message = message;
        this.httpStatus = httpStatus;
    }
}
