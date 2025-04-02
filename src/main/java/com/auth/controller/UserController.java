package com.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.dto.AuthRequestDTO;
import com.auth.dto.UserDTO;
import com.auth.jwt.JwtTokenUtil;
import com.auth.pojo.User;
import com.auth.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
@RequestMapping("/v1/user")
public class UserController {

	@Autowired
	private UserService userService;
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private JwtTokenUtil jwtUtil;

	@PostMapping("/sign-up")
	public ResponseEntity<?> signUp(@RequestBody UserDTO user) {

		if (userService.isUserPresent(user.getEmailId())) {
			return ResponseEntity.status(HttpStatus.OK).body("User already exists. Please try with different email.");
		}
		return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(user));
	}
	
	@PostMapping("/sign-in")
	public ResponseEntity<?> signIn(@RequestBody AuthRequestDTO user) {

		try {
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user.getEmailId(),
					user.getPassword());
			Authentication authenticatedDetails = authManager.authenticate(authToken);
			return ResponseEntity.ok().body(jwtUtil.generateAccessToken(authenticatedDetails));
		} catch (BadCredentialsException e) {

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
		}
	}
	
	@GetMapping("/test")
	public String testAuthentication() {
		return "Authentication working successfully";
	}
	
	
}
