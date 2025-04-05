package com.auth.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth.jwt.JwtTokenFilter;
import com.auth.pojo.RoleType;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

	@Autowired
	private UserDetailsService customUserDetailsService;
	
	@Autowired
	private JwtTokenFilter jwtTokenFilter;

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity
				.authorizeHttpRequests(auth -> auth.requestMatchers("/v1/user/test").hasRole("ADMIN")
						.requestMatchers("/v1/user/sign-up","/v1/user/sign-in","/swagger*/**","/v*/api-docs*/**").permitAll()
						.anyRequest().authenticated())
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> {
					ex.authenticationEntryPoint((request, response, authException) -> response
							.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
				}).addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class).build();
	}
	
	@Bean
	AuthenticationManager authenticatonMgr(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
}
