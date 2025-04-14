package com.auth.pojo;

import java.util.Arrays;

public enum RoleType {

	ROLE_USER, ROLE_ADMIN,ROLE_CUSTOMER;
	
	public static String[] getAllRoleNames() {
		return Arrays.stream(RoleType.values()).map(x -> x.name().replace("ROLE_", "")).toArray(String[]::new);
	}
}
