package com.example.dreambackend.repositories;

import com.example.dreambackend.dtos.SanPhamDto;
import com.example.dreambackend.entities.SanPham;
import com.example.dreambackend.entities.SanPhamChiTiet;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
@Repository
public interface SanPhamOnlineRepository extends JpaRepository<SanPham, Integer> {
    @Query("SELECT new com.example.dreambackend.dtos.SanPhamDto(sp.id, sp.ten, " +
            "(SELECT MIN(spct.gia) FROM SanPhamChiTiet spct WHERE spct.sanPham.id = sp.id), " +
            "(SELECT a.anhUrl FROM Anh a WHERE a.sanPham.id = sp.id ORDER BY a.id ASC LIMIT 1)) " +
            "FROM SanPham sp " +
            "WHERE sp.trangThai = 1 " +
            "AND EXISTS (SELECT 1 FROM Anh a WHERE a.sanPham.id = sp.id)")
    Page<SanPhamDto> getSanPhamChiTietOnline(Pageable pageable);

    @Query("SELECT new com.example.dreambackend.dtos.SanPhamDto(sp.id, sp.ten, " +
            "(SELECT MIN(spct.gia) FROM SanPhamChiTiet spct WHERE spct.sanPham.id = sp.id), " +
            "(SELECT a.anhUrl FROM Anh a WHERE a.sanPham.id = sp.id ORDER BY a.id ASC LIMIT 1)) " +
            "FROM SanPham sp " +
            "WHERE sp.trangThai = 1 " +
            "AND LOWER(sp.ten) LIKE LOWER(CONCAT('%', :ten, '%')) " +
            "AND EXISTS (SELECT 1 FROM Anh a WHERE a.sanPham.id = sp.id)")
    Page<SanPhamDto> searchSanPhamByTen(@org.springframework.data.repository.query.Param("ten") String ten, Pageable pageable);

}

