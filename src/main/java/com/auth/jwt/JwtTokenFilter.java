package com.auth.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtTokenFilter extends OncePerRequestFilter {

	@Autowired
	JwtTokenUtil jwtTokenUtil;

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

		log.debug("[JwtTokenFilter:doFilterInternal] :: Started ");

		log.debug("[JwtTokenFilter:doFilterInternal]Filtering the Http Request:{}", request.getRequestURI());

		if (authHeader != null && authHeader.startsWith("Bearer")) {

			final String token = authHeader.substring(7);
			if (jwtTokenUtil.validateJwtToken(token)) {
				String userName = jwtTokenUtil.getUserName(token);

				if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {

					UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

					UsernamePasswordAuthenticationToken authenticationDetails = new UsernamePasswordAuthenticationToken(
							userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());

					SecurityContextHolder.getContext().setAuthentication(authenticationDetails);

				}
				log.debug("[JwtTokenFilter:doFilterInternal] Completed Successfully");
			} else
				log.error("[JwtTokenFilter:doFilterInternal] Invalid JWT token.");
		} else
			log.error("[JwtTokenFilter:doFilterInternal] Bearer token not found in the request: {}",
					request.getRequestURI());
		filterChain.doFilter(request, response);
	}
}
