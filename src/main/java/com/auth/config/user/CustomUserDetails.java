package com.auth.config.user;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.auth.pojo.User;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

	private static final long serialVersionUID = -5836988047704210939L;

	private User user;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		return user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getRole().name())).toList();
	}

	@Override
	public String getPassword() {

		return user.getPassword();
	}

	@Override
	public String getUsername() {

		return user.getEmailId();
	}

}
