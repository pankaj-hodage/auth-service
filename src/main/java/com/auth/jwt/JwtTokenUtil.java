package com.auth.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtTokenUtil {

	@Value("${EXP_TIMEOUT}")
	private int jwtExpiration;

	@Autowired
	JwtEncoder jwtEncoder;

	public String generateAccessToken(Authentication authentication) {

		log.info("[JwtTokenUtil:generateAccessToken] Token Creation Started for:{}", authentication.getName());

		JwtClaimsSet claims = JwtClaimsSet.builder().issuer("auth-server").issuedAt(Instant.now())
				.expiresAt(Instant.now().plus(jwtExpiration, ChronoUnit.MINUTES)).subject(authentication.getName())
				.build();

		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}

	public boolean validateJwtToken(Jwt jwtToken, UserDetails userDetails) {
		final String userName = getUserName(jwtToken);
		boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
		boolean isTokenUserSameAsDatabase = userName.equals(userDetails.getUsername());
		return !isTokenExpired && isTokenUserSameAsDatabase;
	}

	public String getUserName(Jwt jwtToken) {
		return jwtToken.getSubject();
	}

	private boolean getIfTokenIsExpired(Jwt jwtToken) {
		return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
	}
}
