package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.KhachHang;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface KhachHangRepository extends JpaRepository<KhachHang, Integer> {
    List<KhachHang> findByTenContainingIgnoreCase(String ten);
    KhachHang findKhachHangBySoDienThoai(String soDienThoai);
}