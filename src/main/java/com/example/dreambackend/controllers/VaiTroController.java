package com.example.dreambackend.controllers;

import com.example.dreambackend.entities.VaiTro;
import com.example.dreambackend.services.vaitro.IVaiTroService;
import com.example.dreambackend.services.vaitro.VaiTroService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/vai-tro")
@CrossOrigin(origins = "http://localhost:4200")
public class VaiTroController {

    @Autowired
    private VaiTroService vaiTroService;

    // API lấy danh sách vai trò
    @GetMapping("/hien-thi")
    public ResponseEntity<List<VaiTro>> getAllVaiTros() {
        List<VaiTro> vaiTros = vaiTroService.getAllVaiTros();
        return ResponseEntity.ok(vaiTros);
    }

    // Thêm vai trò mới
    @PostMapping("/add")
    public ResponseEntity<VaiTro> addVaiTro(@RequestBody VaiTro vaiTro) {
        VaiTro savedVaiTro = vaiTroService.addVaiTro(vaiTro);
        return ResponseEntity.ok(savedVaiTro);
    }

    // Cập nhật vai trò
    @PostMapping("/update")
    public ResponseEntity<VaiTro> updateVaiTro(@RequestBody VaiTro vaiTro) {
        VaiTro updatedVaiTro = vaiTroService.updateVaiTro(vaiTro);
        return ResponseEntity.ok(updatedVaiTro);
    }
}
