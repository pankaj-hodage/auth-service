package com.auth.repository;

import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.auth.pojo.RoleType;
import com.auth.pojo.UserRole;

@Repository
public interface RoleRepository extends JpaRepository<UserRole, Long> {

	@Query("SELECT ur FROM UserRole ur WHERE ur.role IN :roles")
	Set<UserRole> findByRoleNameIn(@Param("roles") Set<RoleType> roles);

}
