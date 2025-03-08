package com.example.dreambackend.controllers;

import com.example.dreambackend.entities.NhanVien;
import com.example.dreambackend.services.nhanvien.NhanVienService;
import com.example.dreambackend.ultil.JwtUtil;
import jakarta.annotation.security.PermitAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class LoginController {
    @Autowired
    private NhanVienService nhanVienService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;
    /**
     * API đăng nhập
     */

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String email, @RequestParam String password) {
        try {
            // Step 1: Authenticate the user using the AuthenticationManager
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );

            // Step 2: Load user details after authentication
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Step 3: Generate the JWT token for the authenticated user
            String token = jwtUtil.generateToken(userDetails.getUsername(), "ROLE_USER"); // You can dynamically set the role

            // Step 4: Return the response with JWT token
            return ResponseEntity.ok().body("Bearer " + token);

        } catch (Exception e) {
            // If authentication fails, return an unauthorized status
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email hoặc mật khẩu không đúng.");
        }
    }
}

