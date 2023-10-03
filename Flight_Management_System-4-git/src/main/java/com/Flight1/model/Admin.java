package com.Flight1.model;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Admin {
	@Id
	int admin_id;
	String admin_name;
	String admin_usename;
	String admin_password;
	String admin_email;
	int admin_phone;
	
	
	
	public Admin() {
		super();
	}



	public Admin(int admin_id, String admin_name, String admin_usename, String admin_password, String admin_email,
			int admin_phone) {
		super();
		this.admin_id = admin_id;
		this.admin_name = admin_name;
		this.admin_usename = admin_usename;
		this.admin_password = admin_password;
		this.admin_email = admin_email;
		this.admin_phone = admin_phone;
	}



	public int getAdmin_id() {
		return admin_id;
	}



	public void setAdmin_id(int admin_id) {
		this.admin_id = admin_id;
	}



	public String getAdmin_name() {
		return admin_name;
	}



	public void setAdmin_name(String admin_name) {
		this.admin_name = admin_name;
	}



	public String getAdmin_usename() {
		return admin_usename;
	}



	public void setAdmin_usename(String admin_usename) {
		this.admin_usename = admin_usename;
	}



	public String getAdmin_password() {
		return admin_password;
	}



	public void setAdmin_password(String admin_password) {
		this.admin_password = admin_password;
	}



	public String getAdmin_email() {
		return admin_email;
	}



	public void setAdmin_email(String admin_email) {
		this.admin_email = admin_email;
	}



	public int getAdmin_phone() {
		return admin_phone;
	}



	public void setAdmin_phone(int admin_phone) {
		this.admin_phone = admin_phone;
	}



	@Override
	public String toString() {
		return "Admin [admin_id=" + admin_id + ", admin_name=" + admin_name + ", admin_usename=" + admin_usename
				+ ", admin_password=" + admin_password + ", admin_email=" + admin_email + ", admin_phone=" + admin_phone
				+ "]";
	}
	
	
	
	
	

}
