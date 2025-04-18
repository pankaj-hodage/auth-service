package com.auth.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.auth.jwt.DynamicSecurityFilter;
import com.auth.jwt.JwtAccessTokenFilter;
import com.auth.jwt.JwtRefreshTokenFilter;
import com.auth.service.LogoutHandlerServiceImpl;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(RSAKeyRecord.class)
public class SecurityConfigurations {

	@Autowired
	private JwtAccessTokenFilter jwtAccessTokenFilter;

	@Autowired
	private JwtRefreshTokenFilter jwtRefreshTokenFilter;

	@Autowired
	private DynamicSecurityFilter dynamicSecurityFilter;

	@Autowired
	private LogoutHandlerServiceImpl logoutHandler;

	@Order(1)
	@Bean
	SecurityFilterChain publicAPIsSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity
				.securityMatcher(new OrRequestMatcher(new AntPathRequestMatcher("/user/v1/sign-up"),
						new AntPathRequestMatcher("/user/v1/sign-in"), new AntPathRequestMatcher("/swagger*/**"),
						new AntPathRequestMatcher("/v*/api-docs*/**"), new AntPathRequestMatcher("/error"),
						new AntPathRequestMatcher("/oauth2/google/callback/**"),
						new AntPathRequestMatcher("/actuator/**")))
				.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> {
					ex.authenticationEntryPoint((request, response, authException) -> response
							.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
				}).build();
	}

	@Order(2)
	@Bean
	SecurityFilterChain logOutSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher("/logout/**"))
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults())).csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> {
					ex.authenticationEntryPoint((request, response, authException) -> response
							.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
				}).addFilterBefore(jwtAccessTokenFilter, UsernamePasswordAuthenticationFilter.class)
				.logout(logout -> logout.logoutUrl("/logout").addLogoutHandler(logoutHandler).logoutSuccessHandler(
						((request, response, authentication) -> SecurityContextHolder.clearContext())))
				.build();
	}

	@Order(3)
	@Bean
	SecurityFilterChain refreshTokenSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher("/user/v1/refresh-token"))
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults())).csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> {
					ex.authenticationEntryPoint((request, response, authException) -> response
							.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
				}).addFilterBefore(jwtRefreshTokenFilter, UsernamePasswordAuthenticationFilter.class).build();
	}

	@Order(4)
	@Bean
	SecurityFilterChain testSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher("/user/v1/test"))
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> {
					ex.authenticationEntryPoint((request, response, authException) -> response
							.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
				}).addFilterBefore(jwtAccessTokenFilter, UsernamePasswordAuthenticationFilter.class).build();
	}

	@Order(5)
	@Bean
	SecurityFilterChain dynamicSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults())).csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(dynamicSecurityFilter, UsernamePasswordAuthenticationFilter.class).build();

	}
}
