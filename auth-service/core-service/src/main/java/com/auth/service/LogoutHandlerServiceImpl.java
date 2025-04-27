package com.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import com.auth.pojo.RefreshToken;
import com.auth.repository.RefreshTokenRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class LogoutHandlerServiceImpl implements LogoutHandler {

	@Autowired
	RefreshTokenRepository refreshTokenRepository;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (!authHeader.startsWith(TokenType.BEARER.getValue())) {
			return;
		}

		final String refreshToken = authHeader.substring(7);

		RefreshToken storedRefreshToken = refreshTokenRepository.findByRefreshToken(refreshToken).map(token -> {
			token.setRevoked(true);
			refreshTokenRepository.save(token);
			return token;
		}).orElse(null);
	}
}