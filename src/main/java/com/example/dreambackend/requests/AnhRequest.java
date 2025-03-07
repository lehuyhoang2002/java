package com.example.dreambackend.requests;

import com.example.dreambackend.entities.SanPham;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AnhRequest {
    private Integer id;

    private String anhUrl;

    private LocalDate ngayTao;

    private LocalDate ngaySua;

    private int trangThai;

    private SanPham sanPham;
}
