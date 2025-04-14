//package edu.ecom.authz.security.config;
//
//import edu.ecom.authz.security.filter.AuthorizationFilter;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http,
//        AuthorizationFilter authorizationFilter) throws Exception {
//        http
//            .csrf(AbstractHttpConfigurer::disable)
//            .authorizeHttpRequests(auth -> auth
//                .requestMatchers("/actuator/**", "/public/**").permitAll()
//                .anyRequest().authenticated())
//            .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class);
//        return http.build();
//    }
//}