package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.KhuyenMai;
import com.example.dreambackend.entities.Voucher;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface KhuyenMaiRepository extends JpaRepository<KhuyenMai, Integer> {
    List<KhuyenMai> findByTenContainingIgnoreCase(String ten);
}
