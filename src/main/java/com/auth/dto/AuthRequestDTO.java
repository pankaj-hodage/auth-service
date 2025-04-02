package com.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

public class AuthRequestDTO {

	@NotBlank(message = "Email can't be blank or null")
	private String emailId;
	@NotBlank(message = "password can't be blank or null")
	private String password;

}
