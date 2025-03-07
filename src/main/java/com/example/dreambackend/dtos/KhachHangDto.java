package com.example.dreambackend.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KhachHangDto {

    private String ma;

    private String ten;

    private boolean gioiTinh;

    private String soDienThoai;

    private String matKhau;

    @JsonProperty("ngay_tao")
    private LocalDate ngayTao;
    @JsonProperty("ngay_sua")
    private LocalDate ngaySua;
    @JsonProperty("trang_thai")
    private Integer trangThai;
}
