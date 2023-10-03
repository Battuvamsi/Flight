package com.Flight1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;

@SpringBootApplication
@EnableWebMvc
public class FlightManagementSystem1Application {

	public static void main(String[] args) {
		SpringApplication.run(FlightManagementSystem1Application.class, args);
		
	}
	
	 
	   

}
