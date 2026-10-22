   package com.scamshield_backend;

   import java.util.List;

   import org.springframework.context.annotation.Bean;
   import org.springframework.context.annotation.Configuration;
   import org.springframework.security.config.Customizer;
   import org.springframework.security.config.annotation.web.builders.HttpSecurity;
   import org.springframework.security.web.SecurityFilterChain;
   import org.springframework.web.cors.CorsConfiguration;
   import org.springframework.web.cors.CorsConfigurationSource;
   import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

   @Configuration
   public class SecurityConfig {

       @Bean
       SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
           http
               .cors(Customizer.withDefaults())
               .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
               .authorizeHttpRequests(auth -> auth
                   .requestMatchers("/api/**").permitAll()
                   .anyRequest().authenticated()
               );
           return http.build();
       }

       @Bean
       CorsConfigurationSource corsConfigurationSource() {
           CorsConfiguration config = new CorsConfiguration();
           config.setAllowedOrigins(List.of(
               "https://localhost",
               "http://localhost",
               "capacitor://localhost",
               "https://scamshield-voay.vercel.app"
           ));
           config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
           config.setAllowedHeaders(List.of("*"));
           UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
           source.registerCorsConfiguration("/api/**", config);
           return source;
       }
   }