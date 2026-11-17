package com.scamshield_backend;

public record AuthResponse(String token, String name, String email, String role) {}