package com.auth.jwt;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.auth.dto.AuthResponseDTO;
import com.auth.pojo.RefreshToken;
import com.auth.pojo.User;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.UserRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtTokenUtil {

	@Value("${ACC_TKN_TIMEOUT}")
	private int accessTokenExpiration;
	
	@Value("${REF_TKN_TIMEOUT}")
	private int refreshTokenExpiration;

	@Autowired
	JwtEncoder jwtEncoder;
	
	@Autowired
	private JwtDecoder jwtDecoder;
	
	@Autowired
	RefreshTokenRepository refreshTokenRepository;
	
	@Autowired
	UserRepository userRepository;
	
	public AuthResponseDTO getJwtTokens(Authentication authentication, HttpServletResponse response) {
		try {
			log.info("[JwtTokenUtil:getJwtTokens] Token Creation Started for:{}", authentication.getName());

			final String accessToken = generateAccessToken(authentication.getName());
			final String refreshToken = generateRefreshToken(authentication.getName());

			saveRefreshToken(refreshToken, authentication.getName());
			setRefreshTokenInCookies(response, refreshToken);

			AuthResponseDTO authresponse = AuthResponseDTO.builder().accessToken(accessToken)
					.accessTokenExpiry(LocalDateTime.now().plusMinutes(accessTokenExpiration))
					.userName(authentication.getName()).build();

			return authresponse;

		} catch (Exception e) {
			log.error("[JwtTokenUtil:getJwtTokens]Exception while generating tokens :" + e.getMessage());
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
		}
	}

	private void setRefreshTokenInCookies(HttpServletResponse response,String refreshToken) {
		Cookie cookie = new Cookie("refresh-token", refreshToken);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setMaxAge(refreshTokenExpiration * 24 * 60 * 60 );
        response.addCookie(cookie);		
	}

	private void saveRefreshToken(String refreshToken, String mail) throws Exception {

		User user = userRepository.findByEmailId(mail)
				.orElseThrow(() -> new Exception("User not found with mail : " + mail));
		RefreshToken newRefreshToken = RefreshToken.builder().refreshToken(refreshToken).user(user).revoked(false)
				.build();
		refreshTokenRepository.save(newRefreshToken);
	}

	public String generateAccessToken(String userId) {

		JwtClaimsSet claims = JwtClaimsSet.builder().issuer("auth-server").claim("type", "ACCESS_TOKEN").issuedAt(Instant.now())
				.expiresAt(Instant.now().plus(accessTokenExpiration, ChronoUnit.MINUTES)).subject(userId).build();

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
	
	public String generateRefreshToken(String userId) {
		JwtClaimsSet claims = JwtClaimsSet.builder().issuer("auth-server")
				.claim("type", "REFRESH_TOKEN")
				.claim("scope", "REFRESH_TOKEN_API")
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plus(refreshTokenExpiration, ChronoUnit.DAYS))
				.subject(userId).build();

		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}

	public AuthResponseDTO getAccessTokenFromRefreshToken(HttpServletRequest request) {

		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (authHeader != null && authHeader.startsWith(TokenType.BEARER.getValue())) {
			final String token = authHeader.substring(7);
			Jwt jwtToken = jwtDecoder.decode(token);

			String userName = getUserName(jwtToken);
			boolean isTokenExpired = getIfTokenIsExpired(jwtToken);

			RefreshToken refreshToken = refreshTokenRepository.findByRefreshToken(jwtToken.getTokenValue())
					.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid refresh token."));
			if (!isTokenExpired && !refreshToken.isRevoked() && userName.equals(refreshToken.getUser().getEmailId())) {
				final String accessToken = generateAccessToken(userName);
				AuthResponseDTO authresponse = AuthResponseDTO.builder().accessToken(accessToken)
						.accessTokenExpiry(LocalDateTime.now().plusMinutes(accessTokenExpiration)).userName(userName)
						.build();

				return authresponse;
			}
		} else
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Refresh token not found in header.");
		return new AuthResponseDTO();
	}
}
