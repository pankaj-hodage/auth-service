package com.auth.dto;

import java.util.HashSet;
import java.util.Set;

import com.auth.pojo.RoleType;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {

	@NotBlank(message = "name must be supplied")
	private String name;
	@NotBlank(message = "email must be supplied")
	@Email(message = "Invalid email format")
	private String emailId;
	@NotBlank(message = "password must be supplied")
	private String password;
	@NotEmpty(message = "at least 1 role should be chosen")
	private Set<RoleType> roles = new HashSet<>();

}