package com.Flight1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.Flight1.model.Customer;
import com.Flight1.repository.CustomerRepository;

@Controller
public class ResetPasswordController {

    @Autowired
    private CustomerRepository customerRepository;
    
    @Autowired
    private BCryptPasswordEncoder passwordEncoder; 

    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam("token") String token, Model model) {
        Customer customer = customerRepository.findByResetToken(token);

        if (customer != null && !customer.isResetTokenExpired()) {
            model.addAttribute("resetToken", token);
            return "reset-password";
        } else {
            model.addAttribute("errorMessage", "Invalid or expired token.");
            return "error-page"; // Create an error page to display the message
        }
    }

    @PostMapping("/reset-password")
    public String processResetPasswordForm(@RequestParam("token") String token,
                                           @RequestParam("password") String newPassword, Model model) {
        Customer customer = customerRepository.findByResetToken(token);

        if (customer != null && !customer.isResetTokenExpired()) {
            String encodedPassword = passwordEncoder.encode(newPassword); // Encode the password
            customer.setPassword(encodedPassword);
            customer.setResetToken(null);
            customerRepository.save(customer);
            return "redirect:/login?resetSuccess";
        } else {
            model.addAttribute("errorMessage", "Invalid or expired token.");
            return "error-page"; // Create an error page to display the message
        }
    }
}
