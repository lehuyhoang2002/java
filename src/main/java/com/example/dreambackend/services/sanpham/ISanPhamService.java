package com.example.dreambackend.services.sanpham;

import com.example.dreambackend.entities.SanPham;
import com.example.dreambackend.requests.SanPhamRequest;
import com.example.dreambackend.responses.SanPhamRespone;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface ISanPhamService {
    Page<SanPhamRespone> getAllSanPham(Pageable pageable);

    SanPham addSanPham(SanPhamRequest sanPhamRequest);

    SanPham updateSanPham(SanPhamRequest sanPhamRequest);

    SanPham getSanPhamById(Integer id);

    ResponseEntity<byte[]> exportSanPhamToExcel(List<SanPhamRespone> sanPhams);

    Page<SanPhamRespone> searchSanPham(
            Integer thuongHieuId, Integer xuatXuId, Integer chatLieuId, Integer coAoId, Integer trangThai, String ten, Pageable pageable);
}
