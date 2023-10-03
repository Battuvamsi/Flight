package com.Flight1.controller;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.Flight1.model.Customer;
import com.Flight1.repository.CustomerRepository;
import com.Flight1.service.EmailService;

@Controller
public class ForgotPasswordController {

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private EmailService emailService;

    @GetMapping("/forgot-password")
    public String showForgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPasswordForm(@RequestParam("username") String username, Model model) {
        Customer customer = customerRepository.findByUsername(username).orElse(null);

        if (customer != null) {
            String resetToken = generateResetToken();
            customer.setResetToken(resetToken);
            customerRepository.save(customer);

            sendResetEmail(customer);
            model.addAttribute("successMessage", "Password reset email sent successfully.");
        } else {
            model.addAttribute("errorMessage", "Username not found.");
        }

        return "forgot-password";
    }

    private void sendResetEmail(Customer customer) {
        String resetToken = customer.getResetToken();
        String resetLink = "http://localhost:1045/reset-password?token=" + resetToken; // Replace with actual URL
        String subject = "Password Reset Instructions";
        String text = "To reset your password, click the following link:\n" + resetLink;
        emailService.sendEmail(customer.getCustomer_email(), subject, text);
    }

    private String generateResetToken() {
        // Generate a random UUID as the reset token
        String resetToken = UUID.randomUUID().toString();
        return resetToken;
    }

}
