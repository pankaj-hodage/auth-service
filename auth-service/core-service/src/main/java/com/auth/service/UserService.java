package com.auth.service;

import com.auth.dto.UserDTO;

public interface UserService {

	boolean createUser(UserDTO user);

	boolean isUserPresent(String mail);
}
