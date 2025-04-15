package com.auth.service;

public interface OAuth2Service {

	String handleGoogleCallback(String authCode);
}
