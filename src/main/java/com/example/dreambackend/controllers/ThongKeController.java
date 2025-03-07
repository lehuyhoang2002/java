package com.example.dreambackend.controllers;

import com.example.dreambackend.responses.*;
import com.example.dreambackend.services.thongke.ThongKeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/thong-ke")
@CrossOrigin(origins = "*")
public class ThongKeController {

    @Autowired
    private ThongKeService thongKeService;

    @GetMapping("/{type}")
    public ResponseEntity<ThongKeResponse> thongKeTongQuan(@PathVariable String type) {
        ThongKeResponse response = thongKeService.thongKeTongQuan(type);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/nam-nay/thang")
    public ResponseEntity<List<ThongKeThangResponse>> thongKeTungThang() {
        List<ThongKeThangResponse> response = thongKeService.thongKeTungThang();
        return ResponseEntity.ok(response);
    }
    @GetMapping("/tat-ca/nam")
    public ResponseEntity<List<ThongKeThangResponse>> thongKeTungNam() {
        List<ThongKeThangResponse> response = thongKeService.thongKeTungNam();
        return ResponseEntity.ok(response);
    }
    // Endpoint lấy doanh thu từng ngày trong tháng này
    @GetMapping("/thang-nay/ngay")
    public ResponseEntity<List<ThongKeThangNayResponse>> thongKeTungNgayTrongThang() {
        List<ThongKeThangNayResponse> response = thongKeService.thongKeTungNgayTrongThang();
        return ResponseEntity.ok(response);
    }
    // Endpoint lấy doanh thu ngày hôm nay
    @GetMapping("/hom-nay")
    public ResponseEntity<ThongKeHomNayResponse> thongKeHomNay() {
        ThongKeHomNayResponse response = thongKeService.thongKeHomNay();
        return ResponseEntity.ok(response);
    }
    // Endpoint lấy top sản phẩm bán chạy nhất trong ngày hôm nay
    @GetMapping("/hom-nay/top-san-pham")
    public ResponseEntity<List<TopSanPhamResponse>> topSanPhamHomNay() {
        List<TopSanPhamResponse> response = thongKeService.topSanPhamHomNay();
        return ResponseEntity.ok(response);
    }

    // Endpoint lấy top sản phẩm bán chạy nhất trong tháng này
    @GetMapping("/thang-nay/top-san-pham")
    public ResponseEntity<List<TopSanPhamResponse>> topSanPhamThangNay() {
        List<TopSanPhamResponse> response = thongKeService.topSanPhamThangNay();
        return ResponseEntity.ok(response);
    }

    // Endpoint lấy top sản phẩm bán chạy nhất trong năm nay
    @GetMapping("/nam-nay/top-san-pham")
    public ResponseEntity<List<TopSanPhamResponse>> topSanPhamNamNay() {
        List<TopSanPhamResponse> response = thongKeService.topSanPhamNamNay();
        return ResponseEntity.ok(response);
    }

    // Endpoint lấy top sản phẩm bán chạy nhất tất cả thời gian
    @GetMapping("/tat-ca/top-san-pham")
    public ResponseEntity<List<TopSanPhamResponse>> topSanPhamTatCa() {
        List<TopSanPhamResponse> response = thongKeService.topSanPhamTatCa();
        return ResponseEntity.ok(response);
    }
}
