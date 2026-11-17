package com.scamshield_backend;

import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        String email = request.email().trim().toLowerCase();

        if (userRepository.existsByEmail(email)) {
            return error(HttpStatus.CONFLICT, "An account with this email already exists");
        }

        User user = new User();
        user.setName(request.name().trim());
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.password()));

        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            return error(HttpStatus.CONFLICT, "An account with this email already exists");
        }

        String token = jwtService.generateToken(user.getEmail(), user.getRole());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new AuthResponse(token, user.getName(), user.getEmail(), user.getRole()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        String email = request.email().trim().toLowerCase();

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return error(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }

        LocalDateTime now = LocalDateTime.now();
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
            return error(HttpStatus.TOO_MANY_REQUESTS,
                    "Too many wrong attempts. Please try again after " + LOCK_MINUTES + " minutes");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            int attempts = user.getFailedAttempts() + 1;
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(now.plusMinutes(LOCK_MINUTES));
                attempts = 0;
            }
            user.setFailedAttempts(attempts);
            userRepository.save(user);
            return error(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }

        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        String token = jwtService.generateToken(user.getEmail(), user.getRole());
        return ResponseEntity.ok(
                new AuthResponse(token, user.getName(), user.getEmail(), user.getRole()));
    }
    // Returns the logged-in user's details. Needs a valid token.
    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .map(u -> ResponseEntity.ok(Map.of(
                        "name", u.getName(),
                        "email", u.getEmail(),
                        "role", u.getRole())))
                .orElseGet(() -> error(HttpStatus.UNAUTHORIZED, "User not found"));
    }

    // Turns validation problems into a simple message the React page can show
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(e -> e.getDefaultMessage())
                .orElse("Invalid input");
        return error(HttpStatus.BAD_REQUEST, message);
    }

    private ResponseEntity<Map<String, String>> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of("message", message));
    }
}