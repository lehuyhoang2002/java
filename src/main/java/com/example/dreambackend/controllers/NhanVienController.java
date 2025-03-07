package com.example.dreambackend.controllers;

import com.example.dreambackend.entities.NhanVien;
import com.example.dreambackend.services.nhanvien.INhanVienService;
import com.example.dreambackend.services.nhanvien.NhanVienService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/nhan-vien")
@CrossOrigin(origins = "http://localhost:4200")
public class NhanVienController {

    @Autowired
    private NhanVienService nhanVienService;

    // Hiển thị danh sách nhân viên có phân trang
    @GetMapping("/hien-thi")
    public ResponseEntity<Page<NhanVien>> hienThiPaged(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "8") int size) {
        Page<NhanVien> pagedNhanViens = nhanVienService.getAllNhanVienPaged(page, size);
        return ResponseEntity.ok(pagedNhanViens);
    }

    // Thêm nhân viên mới (bao gồm thông tin vai trò nếu có)
    @PostMapping("/add")
    public ResponseEntity<NhanVien> addNhanVien(@RequestBody NhanVien nhanVien) {
        System.out.println("Received nhanVien: " + nhanVien);
        NhanVien savedNhanVien = nhanVienService.addNhanVien(nhanVien);
        return ResponseEntity.ok(savedNhanVien);
    }

    // Cập nhật nhân viên
    @PostMapping("/update")
    public ResponseEntity<NhanVien> updateNhanVien(@RequestBody NhanVien nhanVien) {
        NhanVien updatedNhanVien = nhanVienService.updateNhanVien(nhanVien);
        return ResponseEntity.ok(updatedNhanVien);
    }

    // Tìm kiếm nhân viên theo tên
    @GetMapping("/search")
    public List<NhanVien> searchNhanVienByName(@RequestParam("ten") String ten) {
        return nhanVienService.searchNhanVienByName(ten);
    }

    // Lấy chi tiết nhân viên theo id
    @GetMapping("/{id}")
    public ResponseEntity<NhanVien> getNhanVienDetail(@PathVariable Integer id) {
        try {
            NhanVien nhanVien = nhanVienService.getNhanVienById(id);
            return ResponseEntity.ok(nhanVien);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}
