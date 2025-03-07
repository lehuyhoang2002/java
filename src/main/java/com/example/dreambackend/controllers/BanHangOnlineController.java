package com.example.dreambackend.controllers;

import com.example.dreambackend.dtos.SanPhamDto;
import com.example.dreambackend.services.sanphamonline.SanPhamOnlineService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ban-hang-online")
@CrossOrigin(origins = "http://localhost:4201")
public class BanHangOnlineController {
    @Autowired
    SanPhamOnlineService sanPhamOnlineService;
    @GetMapping("/hien-thi")
    public ResponseEntity<Page<SanPhamDto>> hienThi(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "16") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        Page<SanPhamDto> sanPhamDtos = sanPhamOnlineService.getSanPhamOnline(pageable);
        return ResponseEntity.ok(sanPhamDtos);
    }

    // ✅ API tìm kiếm sản phẩm theo tên
    @GetMapping("/tim-kiem")
    public ResponseEntity<Page<SanPhamDto>> timKiemSanPham(
            @RequestParam String ten,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<SanPhamDto> result = sanPhamOnlineService.timKiemSanPham(ten, pageable);
        return ResponseEntity.ok(result);
    }
}
