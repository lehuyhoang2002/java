package com.example.dreambackend.controllers;

import com.example.dreambackend.requests.HoaDonRequest;
import com.example.dreambackend.responses.HoaDonResponse;
import com.example.dreambackend.services.hoadon.IHoaDonService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/hoa-don")
public class HoaDonController {

    @Autowired
    private IHoaDonService hoaDonService;

    @PostMapping("/create")
    public ResponseEntity<?> createHoaDon(@RequestBody HoaDonRequest request) {
        try {
            HoaDonResponse response = hoaDonService.createHoaDon(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/{id}/update")
    public ResponseEntity<?> updateHoaDon(@PathVariable Integer id, @RequestBody HoaDonRequest request) {
        try {
            HoaDonResponse response = hoaDonService.updateHoaDon(id, request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

//    @DeleteMapping("/{id}/delete")
//    public ResponseEntity<?> deleteHoaDon(@PathVariable Integer id) {
//        try {
//            hoaDonService.deleteHoaDon(id);
//            return ResponseEntity.noContent().build();
//        } catch (RuntimeException e) {
//            return ResponseEntity.badRequest().body(e.getMessage());
//        }
//    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getHoaDonById(@PathVariable Integer id) {
        try {
            HoaDonResponse response = hoaDonService.findById(id);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/all")
    public ResponseEntity<List<HoaDonResponse>> getAllHoaDon() {
        List<HoaDonResponse> response = hoaDonService.getAllHoaDon();
        return ResponseEntity.ok(response);
    }
}

