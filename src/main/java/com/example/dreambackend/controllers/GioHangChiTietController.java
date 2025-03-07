package com.example.dreambackend.controllers;

import com.example.dreambackend.requests.GioHangChiTietRequest;
import com.example.dreambackend.responses.GioHangChiTietResponse;
import com.example.dreambackend.services.giohangchitiet.IGioHangChiTietService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/gio-hang")
public class GioHangChiTietController {

    @Autowired
    private IGioHangChiTietService gioHangChiTietService;


    @PostMapping("/{khachHangId}/add")
    public ResponseEntity<GioHangChiTietResponse> addToGioHang(
            @PathVariable Integer khachHangId,
            @RequestBody GioHangChiTietRequest request) {
        GioHangChiTietResponse response = gioHangChiTietService.addToGioHang(khachHangId, request);
        return ResponseEntity.ok(response);
    }


    @PutMapping("/{gioHangChiTietId}/update")
    public ResponseEntity<GioHangChiTietResponse> updateSoLuong(
            @PathVariable Integer gioHangChiTietId,
            @RequestParam Integer soLuong) {
        GioHangChiTietResponse response = gioHangChiTietService.updateSoLuong(gioHangChiTietId, soLuong);
        return ResponseEntity.ok(response);
    }


    @DeleteMapping("/{gioHangChiTietId}/remove")
    public ResponseEntity<Void> removeFromGioHang(@PathVariable Integer gioHangChiTietId) {
        gioHangChiTietService.removeFromGioHang(gioHangChiTietId);
        return ResponseEntity.noContent().build();
    }


    @GetMapping("/{khachHangId}")
    public ResponseEntity<List<GioHangChiTietResponse>> getGioHangByKhachHang(@PathVariable Integer khachHangId) {
        List<GioHangChiTietResponse> response = gioHangChiTietService.getGioHangByKhachHang(khachHangId);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{khachHangId}/clear")
    public ResponseEntity<Void> clearGioHang(@PathVariable Integer khachHangId) {
        gioHangChiTietService.clearGioHang(khachHangId);
        return ResponseEntity.noContent().build();
    }
}
