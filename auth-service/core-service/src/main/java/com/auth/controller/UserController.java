package com.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.dto.AuthRequestDTO;
import com.auth.dto.UserDTO;
import com.auth.jwt.JwtTokenUtil;
import com.auth.service.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/user/v1")
public class UserController {

	@Autowired
	private UserService userService;

	@Autowired
	private AuthenticationManager authManager;

	@Autowired
	private JwtTokenUtil jwtUtil;

	@Operation(description = "Sign up for new user")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "201", description = "New User created", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class), examples = {
					@ExampleObject(name = "Success", value = "true") })),
			@ApiResponse(responseCode = "200", description = "User already exists. Please try with different email.", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class), examples = {
					@ExampleObject(name = "Success", value = "User already exists. Please try with different email.") })) })
	@PostMapping("/sign-up")
	public ResponseEntity<?> signUp(@Validated @RequestBody UserDTO user) {

		if (userService.isUserPresent(user.getEmailId())) {
			return ResponseEntity.status(HttpStatus.OK).body("User already exists. Please try with different email.");
		}
		return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(user));
	}

	@PostMapping("/sign-in")
	public ResponseEntity<?> signIn(@Validated @RequestBody AuthRequestDTO user, HttpServletResponse response) {

		try {
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user.getEmailId(),
					user.getPassword());
			Authentication authenticatedDetails = authManager.authenticate(authToken);
			return ResponseEntity.ok().body(jwtUtil.getJwtTokens(user.getEmailId(), response));
		} catch (BadCredentialsException e) {

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
		}
	}

	@GetMapping("/refresh-token")
	@PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN_API')")
	public ResponseEntity<?> getAccessTokenFromRefreshToken(HttpServletRequest request) {
		return ResponseEntity.ok(jwtUtil.getAccessTokenFromRefreshToken(request));
	}

	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	@GetMapping("/test")
	public String testAuthentication() {
		return "Authentication working successfully";
	}

}
