package com.Flight1.model;

import java.time.LocalDateTime;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Customer {
	

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	int customer_id;
	String customer_name;
	String username;
	String password;
	String customer_email;
	String customer_phone;
	String role;
	
	  String resetToken;
	    LocalDateTime resetTokenExpiry;

	    public boolean isResetTokenExpired() {
	        return resetTokenExpiry != null && resetTokenExpiry.isBefore(LocalDateTime.now());
	    }
	
	
	
	public Customer() {
		super();
	}
	
	
	
	public Customer(int customer_id, String customer_name, String username, String password, String customer_email,
			String customer_phone, String role) {
		super();
		this.customer_id = customer_id;
		this.customer_name = customer_name;
		this.username = username;
		this.password = password;
		this.customer_email = customer_email;
		this.customer_phone = customer_phone;
		this.role = role;
	}













	public String getResetToken() {
		return resetToken;
	}



	public void setResetToken(String resetToken) {
		this.resetToken = resetToken;
	}



	public LocalDateTime getResetTokenExpiry() {
		return resetTokenExpiry;
	}



	public void setResetTokenExpiry(LocalDateTime resetTokenExpiry) {
		this.resetTokenExpiry = resetTokenExpiry;
	}



	public int getCustomer_id() {
		return customer_id;
	}



	public void setCustomer_id(int customer_id) {
		this.customer_id = customer_id;
	}



	public String getCustomer_name() {
		return customer_name;
	}



	public void setCustomer_name(String customer_name) {
		this.customer_name = customer_name;
	}






	public String getUsername() {
		return username;
	}



	public void setUsername(String username) {
		this.username = username;
	}



	public String getPassword() {
		return password;
	}



	public void setPassword(String password) {
		this.password = password;
	}



	public String getRole() {
		return role;
	}



	public void setRole(String role) {
		this.role = role;
	}



	public String getCustomer_email() {
		return customer_email;
	}



	public void setCustomer_email(String customer_email) {
		this.customer_email = customer_email;
	}



	public String getCustomer_phone() {
		return customer_phone;
	}



	public void setCustomer_phone(String customer_phone) {
		this.customer_phone = customer_phone;
	}



	
	
	
	

}
