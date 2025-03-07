package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.NhanVien;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface NhanVienRepository extends JpaRepository<NhanVien, Integer> {
    List<NhanVien> findByTenContainingIgnoreCase(String ten);
    // Tìm nhân viên dựa trên email
    Optional<NhanVien> findByEmail(String email);
    NhanVien findByTaiKhoan(String taiKhoan);
}
