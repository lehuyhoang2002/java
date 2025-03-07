package com.example.dreambackend.responses;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class HoaDonResponse {
    private Integer id;
    private Integer idKhachHang;
    private Integer idNhanVien;
    private Integer idVoucher;
    private Integer idPhuongThucThanhToan;
    private String tenNguoiNhan;
    private String sdtNguoiNhan;
    private String diaChiNhanHang;
    private String hinhThucThanhToan;
    private Double phiVanChuyen;
    private Double tongTienTruocVoucher;
    private Double tongTienThanhToan;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate ngayNhanDuKien;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate ngayTao;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate ngaySua;
    private Integer trangThai;
    private String ghiChu;
}
