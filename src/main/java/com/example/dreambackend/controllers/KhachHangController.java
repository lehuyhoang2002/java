package com.example.dreambackend.controllers;

import com.example.dreambackend.dtos.KhachHangDto;
import com.example.dreambackend.entities.KhachHang;
import com.example.dreambackend.services.khachhang.KhachHangService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/khach-hang")
@CrossOrigin(origins = "http://localhost:4200")
public class KhachHangController {
    @Autowired
    KhachHangService khachHangService;

    @GetMapping("/hien-thi")
    public ResponseEntity<Page<KhachHang>> hienThiPaged(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "8") int size) {
        Page<KhachHang> pagedKhachHangs = khachHangService.getAllKhachHangPaged(page, size);
        return ResponseEntity.ok(pagedKhachHangs);
    }
    @PostMapping("/add")
    public ResponseEntity<KhachHang> addKhachHang(@RequestBody KhachHangDto khachHangDto){
        return ResponseEntity.ok(khachHangService.addKhachHang(khachHangDto));
    }

    @PostMapping("/update")
    public ResponseEntity<?> updateKhachHang( @RequestBody KhachHang khachHang) {
        KhachHang updatedKhachHang = khachHangService.updateKhachHang(khachHang);
        return ResponseEntity.ok(updatedKhachHang);
    }

    @GetMapping("/search")
    public List<KhachHang> searchKhachHangByName(@RequestParam("ten") String ten) {
        return khachHangService.searchKhachHangByName(ten);
    }
    @PutMapping("/{id}")
    public ResponseEntity<KhachHang> getKhachHangDetail(@PathVariable Integer id) {
        KhachHang khachHang= khachHangService.getKhachHangById(id);
        return ResponseEntity.ok(khachHang);
    }
    @GetMapping("/sdt")
    public KhachHang getKhachHangByid(@RequestParam("soDienThoai") String soDienThoai) {
        return khachHangService.getKhachHangBySoDienThoai(soDienThoai);
    }
}