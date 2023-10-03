package com.Flight1.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.factory.annotation.Autowired;

@Controller
public class UserController {

    private final UserDetailsService userDetailsService;

    @Autowired
    public UserController(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/login") // Add this GET endpoint
    public String showLoginForm() {
        return "login"; // Return the name of your Thymeleaf template for the login page
    }

    
    
    @GetMapping("/logout") // Add this GET endpoint for handling logout
    public String logout() {
        // Code to handle logout and invalidate session (if using sessions)
        return "redirect:/login"; // Redirect to the login page after logout
    }
    

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getName());

        if (userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ADMIN"))) {
            return "admin-dashboard";
        } else if (userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("CUSTOMER"))) {
            return "customer-dashboard";
        } else {
            model.addAttribute("unknownRole", true);
            return "dashboard";
        }
    }

    @GetMapping("/admin")
    public String adminDashboard() {
        
        return "admin-dashboard"; // Return the name of your Thymeleaf template for admin dashboard
    }

    @GetMapping("/customer")
    public String customerDashboard() {
        // Your customer dashboard logic here...
        return "customer-dashboard"; // Return the name of your Thymeleaf template for customer dashboard
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (userDetails.getPassword().equals(password)) {
                if (userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))) {
                    return "redirect:/admin";
                } else if (userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_CUSTOMER"))) {
                    return "redirect:/customer";
                }
            }
        } catch (UsernameNotFoundException e) {
            // User with the given username not found, handle accordingly
        }

        // If login fails, redirect back to the login page
        return "redirect:/login";
    }
}
