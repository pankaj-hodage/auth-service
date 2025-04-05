package com.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class SwaggerConfig {

	@Bean
	static OpenAPI openAPIMetaInfo() {
		return new OpenAPI().info(new Info().title("API Documentation Auth Application")
				.description("API developer portal documentation Auth Application").version("v1"));
	}
}
