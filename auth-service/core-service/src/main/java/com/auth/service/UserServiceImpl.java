package com.auth.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.dto.UserDTO;
import com.auth.pojo.User;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService {

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Override
	public boolean createUser(UserDTO user) {

		User newUser = User.builder().userName(user.getName()).emailId(user.getEmailId())
				.password(passwordEncoder.encode(user.getPassword()))
				.roles(roleRepository.findByRoleNameIn(user.getRoles())).build();

		userRepository.save(newUser);
		log.debug("[UserServiceImpl:createUser] user added : {}", newUser.toString());
		return true;
	}

	@Override
	public boolean isUserPresent(String mail) {
		Optional<User> userDetails = userRepository.findByEmailId(mail);
		return userDetails.isPresent();
	}

}
