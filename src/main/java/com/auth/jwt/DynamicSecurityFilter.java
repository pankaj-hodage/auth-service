package com.auth.jwt;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class DynamicSecurityFilter extends OncePerRequestFilter {

	private Set<String> endpoints;

	private Set<String> targetPackages;

	@Qualifier("requestMappingHandlerMapping")
	@Autowired
	private RequestMappingHandlerMapping requestMappingHandlerMapping;

	@Value("${security.filter.packages}")
	private String[] securityFilterPackages;

	@Value("${server.servlet.context-path}")
	private String contextPath;

	@Override
	protected void initFilterBean() throws ServletException {
		super.initFilterBean();

		targetPackages = new HashSet<>(Arrays.asList(securityFilterPackages));
		contextPath = StringUtils.hasText(contextPath) ? contextPath : "";

		endpoints = requestMappingHandlerMapping.getHandlerMethods().entrySet().stream().filter(entry -> {
			String packageName = entry.getValue().getBeanType().getPackage().getName();
			return targetPackages.stream().anyMatch(packageName::startsWith);
		}).map(entry -> entry.getKey().getPathPatternsCondition().getPatterns()).flatMap(Set::stream)
				.collect(Collectors.toSet()).stream().map(path -> path.getPatternString()).collect(Collectors.toSet());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String requestURI = request.getServletPath();

		if (endpoints.contains(requestURI) && SecurityContextHolder.getContext().getAuthentication() == null) {
			log.error("[DynamicSecurityFilter:doFilterInternal] Authentication not set to access restricted API's");
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized request");
		}
		filterChain.doFilter(request, response);
	}
}
