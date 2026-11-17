package com.scamshield_backend;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Name is required")
        @Size(max = 80, message = "Name is too long")
        String name,

        @NotBlank(message = "Email is required")
        @Email(message = "Enter a valid email")
        @Size(max = 120, message = "Email is too long")
        String email,

        @NotBlank(message = "Password is required")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).{8,64}$",
                 message = "Password must be 8 to 64 characters with at least one letter and one number")
        String password
) {}