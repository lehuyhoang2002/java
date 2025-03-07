package com.example.dreambackend.repositories;

import com.example.dreambackend.entities.GioHangChiTiet;
import com.example.dreambackend.entities.KhachHang;
import com.example.dreambackend.entities.SanPhamChiTiet;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface GioHangChiTietRepository extends JpaRepository<GioHangChiTiet,Integer> {
    List<GioHangChiTiet> findByKhachHangAndSanPhamChiTiet(KhachHang khachHang, SanPhamChiTiet sanPhamChiTiet);


    List<GioHangChiTiet> findByKhachHang(KhachHang khachHang);
}
