package com.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auth.jwt.JwtTokenUtil;
import com.auth.service.OAuth2Service;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/oauth2/")
public class OAuthController {

	@Autowired
	private OAuth2Service oAuth2Service;

	@Autowired
	private JwtTokenUtil jwtUtil;

	@GetMapping("google/callback")
	public ResponseEntity<?> handleGoogleCallback(HttpServletResponse response,
			@RequestParam("authCode") String authCode) {
		String userMailId = oAuth2Service.handleGoogleCallback(authCode);
		if (userMailId != null) {
			return ResponseEntity.ok().body(jwtUtil.generateTokensforOAuth2Clients(userMailId, response));
		}
		return ResponseEntity.badRequest().build();
	}
}
