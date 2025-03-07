package com.example.dreambackend.responses;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TopSanPhamResponse {
    private String tenSanPham;
    private Long tongSoLuong;
}
