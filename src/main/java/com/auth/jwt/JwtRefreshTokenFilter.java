package com.auth.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import com.auth.repository.RefreshTokenRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

	@Autowired
	JwtTokenUtil jwtTokenUtil;

	@Autowired
	UserDetailsService userDetailsService;

	@Autowired
	private JwtDecoder jwtDecoder;

	@Autowired
	RefreshTokenRepository refreshTokenRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

			log.debug("[JwtRefreshTokenFilter:doFilterInternal] :: Started ");

			log.debug("[JwtRefreshTokenFilter:doFilterInternal]Filtering the Http Request:{}", request.getRequestURI());

			if (authHeader != null && authHeader.startsWith(TokenType.BEARER.getValue())) {

				final String token = authHeader.substring(7);
				final Jwt jwtToken = jwtDecoder.decode(token);
				final String userName = jwtTokenUtil.getUserName(jwtToken);

				if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {

					boolean isRefreshTokenValidInDatabase = refreshTokenRepository
							.findByRefreshToken(jwtToken.getTokenValue())
							.map(refreshTokenEntity -> !refreshTokenEntity.isRevoked()).orElse(false);

					UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

					if (isRefreshTokenValidInDatabase && jwtTokenUtil.validateJwtToken(jwtToken, userDetails)) {
						UsernamePasswordAuthenticationToken authenticationDetails = new UsernamePasswordAuthenticationToken(
								userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());

						SecurityContextHolder.getContext().setAuthentication(authenticationDetails);
					} else
						log.error("[JwtRefreshTokenFilter:doFilterInternal] Invalid JWT token.");

					log.debug("[JwtRefreshTokenFilter:doFilterInternal] Completed Successfully");

				}

			}
		} catch (Exception jwtException) {
			log.error("[JwtRefreshTokenFilter:doFilterInternal] Exception due to :{}", jwtException.getMessage());
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtException.getMessage());
		}

		filterChain.doFilter(request, response);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !request.getServletPath().equals("/user/v1/refresh-token");
	}
}
