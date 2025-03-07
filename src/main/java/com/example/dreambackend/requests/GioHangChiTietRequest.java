package com.example.dreambackend.requests;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GioHangChiTietRequest {
    private Integer soLuong;

    private Double donGia;

    private String ngayTao;

    private String ngaySua;

    private Integer trangThai;

    private Integer idKhachHang;

    private Integer idSanPhamChiTiet;
}
