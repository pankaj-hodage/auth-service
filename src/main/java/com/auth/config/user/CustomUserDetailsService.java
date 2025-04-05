package com.auth.config.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@Slf4j
public class CustomUserDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepo;
	
	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		
		return userRepo
                .findByEmailId(userName)
                .map(CustomUserDetails::new)
                .orElseThrow(()-> {
                	log.error("[AuthService:userSignInAuth] User :{} not found",userName);
                	return new UsernameNotFoundException("UserEmail: "+userName+" does not exist");});
	}

}
