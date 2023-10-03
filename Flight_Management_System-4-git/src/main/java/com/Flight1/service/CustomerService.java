package com.Flight1.service;

import java.util.List;

import com.Flight1.model.Customer;

public interface CustomerService {

	Customer registerCustomer(Customer customer);

	//void resetPassword(String username, String newPassword);

	Customer updateCustomer(Customer customer);

	void deleteCustomer(int customer_id);

	//void resetPassword(Long customer_id, String newPassword);

	//void resetPassword(String customer_name, String newPassword);

	void resetPassword(int customer_id, String newPassword);

	List<Customer> getAllCustomers();

	Customer getCustomerById(int customerId);

	Customer getCustomerProfile(int customerId);

	//void resetPassword(Long customer_id, String newPassword);

}
