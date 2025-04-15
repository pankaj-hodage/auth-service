package com.auth.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.auth.jwt.JwtTokenUtil;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@Slf4j
public class OAuth2ServiceImpl implements OAuth2Service {

	@Value("${oauth2.google.authcode-verification-url}")
	private String googleAuthCodeEndpoint;

	@Value("${oauth2.google.redirect-url}")
	private String googleRedirectUrl;

	@Value("${oauth2.google.user-info-url}")
	private String googleuserInfoUrl;

	@Value("${oauth2.client.registration.google.client-id}")
	private String clientId;

	@Value("${oauth2.client.registration.google.client-secret}")
	private String clientSecret;

	@Autowired
	private RestTemplate restTemplate;

	@Autowired
	JwtTokenUtil jwtTokenUtil;

	@Override
	public String handleGoogleCallback(String authCode) {

		String userMailId = null;
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", authCode);
		params.add("client_id", clientId);
		params.add("client_secret", clientSecret);
		params.add("redirect_uri", googleRedirectUrl);
		params.add("grant_type", "authorization_code");
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
		ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(googleAuthCodeEndpoint, request, Map.class);
		String idToken = (String) tokenResponse.getBody().get("id_token");
		ResponseEntity<Map> userInfoResponse = restTemplate.getForEntity(googleuserInfoUrl + idToken, Map.class);
		if (userInfoResponse.getStatusCode() == HttpStatus.OK) {
			Map<String, Object> userInfo = userInfoResponse.getBody();
			userMailId = (String) userInfo.get("email");
		}
		return userMailId;
	}

}
