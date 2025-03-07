package com.example.dreambackend.controllers;

import com.example.dreambackend.entities.NhanVien;
import com.example.dreambackend.services.nhanvien.NhanVienService;
import jakarta.annotation.security.PermitAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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

    /**
     * API đăng nhập
     */

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String email, @RequestParam String password) {
        // Gọi phương thức login từ NhanVienService để kiểm tra thông tin và thực hiện đăng nhập
        ResponseEntity<?> nhanVien = nhanVienService.login(email, password);

        if (nhanVien != null) {
            // Nếu đăng nhập thành công, trả về thông tin nhân viên
            return ResponseEntity.ok(nhanVien);
        } else {
            // Nếu thông tin đăng nhập sai, trả về lỗi 401 Unauthorized
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email hoặc mật khẩu không đúng.");
        }
    }
    }

