package com.example.dreambackend.controllers;

import com.example.dreambackend.entities.Anh;
import com.example.dreambackend.responses.AnhRespone;
import com.example.dreambackend.services.anh.AnhService;
import com.example.dreambackend.services.sanpham.SanPhamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/anh")
@CrossOrigin(origins = "http://localhost:4200")
public class AnhController {
    @Autowired
    AnhService anhService;

    @Autowired
    SanPhamService sanPhamService;

    @Configuration
    public class WebMvcConfig implements WebMvcConfigurer {
        @Override
        public void addResourceHandlers(ResourceHandlerRegistry registry) {
            registry.addResourceHandler("/uploads/images/**")
                    .addResourceLocations("file:D:/dream-store/dream-backend/uploads/images/");
        }
    }

    @GetMapping("/hien-thi")
    public ResponseEntity<List<AnhRespone>> hienThi(@RequestParam(value = "idSanPham") Integer idSanPham) {
        List<AnhRespone> listAnh = anhService.getAllAnh(idSanPham);
        return ResponseEntity.ok(listAnh);
    }
    @PostMapping(value = "/add", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> addAnhs(
            @RequestParam("anhUrl") List<MultipartFile> anhUrls,
            @RequestParam("idSanPham") Integer idSanPham) {
        List<Anh> addedAnhs = anhService.addAnhs(anhUrls, idSanPham);
        return ResponseEntity.ok(Map.of("message","Đã tải lên " + addedAnhs.size() + " ảnh thành công"));
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteAnh(@PathVariable("id") Integer id) {
        anhService.deleteAnh(id);
        return ResponseEntity.ok(Map.of("message", "Ảnh đã được xóa thành công"));
    }

}