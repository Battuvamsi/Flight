package com.Flight1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Flight1.model.Customer;
import com.Flight1.service.CustomerService;
@Controller
@RequestMapping("/v2")
public class CustomerController {
	
	@Autowired
	CustomerService customerser;
	
	@Autowired
	private PasswordEncoder encoder;
	

    @GetMapping("/customer-profile")
    public ResponseEntity<Customer> getCustomerProfile(@RequestParam("customer_id") int customerId) throws NotFoundException {
        try {
            Customer customer = customerser.getCustomerProfile(customerId);
            return ResponseEntity.ok(customer);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
	
	
	
	 @GetMapping("/profile")
	    public ResponseEntity<Customer> getLoggedInCustomerDetails(@RequestParam("customerId") int customerId) {
	        Customer customer = customerser.getCustomerById(customerId);
	        if (customer != null) {
	            return ResponseEntity.ok(customer);
	        } else {
	            return ResponseEntity.notFound().build();
	        }
	    }
	
//	  @PostMapping("/register")
//	    public ResponseEntity<Customer> registerCustomer(@RequestBody Customer customer) {
//		  customer.setPassword(encoder.encode(customer.getPassword()));
//	        Customer registeredCustomer = customerser.registerCustomer(customer);
//	       
//	        return ResponseEntity.ok(registeredCustomer);
//	    } 
	  
	 @GetMapping("/register")
	    public String showRegistrationForm(Model model) {
	        model.addAttribute("customer", new Customer());
	        return "register";
	    }
//	    
//	    @PostMapping("/register")
//	    public String registerCustomer(@ModelAttribute("customer") Customer customer) {
//	        customer.setPassword(encoder.encode(customer.getPassword()));
//	        Customer registeredCustomer = customerser.registerCustomer(customer);
//	        
//	        // Perform any necessary logic or database operations
//	        
//	        return "redirect:/registration-success"; // Redirect to success page
	 @PostMapping("/register")
	 public String registerCustomer(@ModelAttribute("customer") Customer customer) {
	     if (customer.getPassword() != null && !customer.getPassword().isEmpty()) {
	         customer.setPassword(encoder.encode(customer.getPassword()));
	     }
	     Customer registeredCustomer = customerser.registerCustomer(customer);

	     // Perform any necessary logic or database operations

	     return "redirect:/v2/registration-success"; // Redirect to success page
	 }


 // Return the name of the HTML page
	  
	    
	  @GetMapping("/registration-success")
	  public String showRegistrationSuccessPage() {
	      return "registration-success";
	  }

	  
	  @PostMapping("/resetPassword")
	    public ResponseEntity<String> resetPassword(@RequestParam int customer_id, @RequestParam String newPassword) {
	        customerser.resetPassword(customer_id, newPassword);
	        return ResponseEntity.ok("Password reset successfully");
	    }
	    
	    @PutMapping("/update")
	    public ResponseEntity<Customer> updateCustomer(@RequestBody Customer customer) {
	        Customer updatedCustomer = customerser.updateCustomer(customer);
	        return ResponseEntity.ok(updatedCustomer);
	    }
	    
	    @DeleteMapping("/delete/{customer_id}")
	    //@PreAuthorize("hasRole('CUSTOMER')")
	    public ResponseEntity<String> deleteCustomer(@PathVariable("customer_id") int customer_id) {
	        customerser.deleteCustomer(customer_id);
	        return ResponseEntity.ok("Customer deleted successfully");
	    }

}

