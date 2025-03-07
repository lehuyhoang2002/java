package com.example.dreambackend.services.phanquyen;

import com.example.dreambackend.entities.NhanVien;
import com.example.dreambackend.repositories.NhanVienRepository;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private NhanVienRepository nhanVienRepository;  // Dịch vụ nhân viên để lấy thông tin người dùng

    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Fetch the NhanVien using Optional and handle not found scenario
        Optional<NhanVien> optionalNhanVien = nhanVienRepository.findByEmail(email);
        NhanVien nhanVien = optionalNhanVien
                .orElseThrow(() -> new UsernameNotFoundException("Nhân viên không tồn tại với email: " + email));

        if (nhanVien.getMatKhau() == null || nhanVien.getMatKhau().isEmpty()) {
            throw new UsernameNotFoundException("Mật khẩu không chính xác với email: " + email);
        }

        return User.builder()
                .username(nhanVien.getEmail())
                .password(nhanVien.getMatKhau())
                .roles(nhanVien.getVaiTro().getTen())
                .build();
    }



}
