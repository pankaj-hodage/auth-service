package com.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth.jwt.JwtAccessTokenFilter;
import com.auth.jwt.JwtRefreshTokenFilter;
import com.auth.pojo.RoleType;
import com.auth.service.LogoutHandlerServiceImpl;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(RSAKeyRecord.class)
public class SecurityConfigurations {

	@Autowired
	private JwtAccessTokenFilter jwtAccessTokenFilter;

	@Autowired
	private JwtRefreshTokenFilter jwtRefreshTokenFilter;

	@Autowired
	private LogoutHandlerServiceImpl logoutHandler;

	@Bean
	SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity
				.authorizeHttpRequests(auth -> auth.requestMatchers("/user/v1/test").hasRole("ADMIN")
						.requestMatchers("/user/v1/refresh-token", "/logout/**").hasAnyRole(RoleType.getAllRoleNames())
						.requestMatchers("/user/v1/sign-up", "/user/v1/sign-in", "/swagger*/**", "/v*/api-docs*/**",
								"/error", "/oauth2/google/callback/**")
						.permitAll().anyRequest().authenticated())
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> {
					ex.authenticationEntryPoint((request, response, authException) -> response
							.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
				})
				.logout(logout -> logout.logoutUrl("/logout").addLogoutHandler(logoutHandler).logoutSuccessHandler(
						((request, response, authentication) -> SecurityContextHolder.clearContext())))
				.addFilterBefore(jwtAccessTokenFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(jwtRefreshTokenFilter, UsernamePasswordAuthenticationFilter.class).build();
	}
}
