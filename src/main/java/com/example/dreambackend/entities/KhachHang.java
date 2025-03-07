package com.example.dreambackend.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "khach_hang")
public class KhachHang {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "ma", nullable = false,length = 10)
    private String ma;

    @Column(name = "ten", length = 30)
    private String ten;

    @Column(name = "gioi_tinh")
    private Boolean gioiTinh;

    @Column(name = "so_dien_thoai")
    private String soDienThoai;

    @Column(name = "mat_khau")
    private String matKhau;

    @Column(name = "ngay_tao")
    private LocalDate ngayTao;

    @Column(name = "ngay_sua")
    private LocalDate ngaySua;

    @Column(name = "trang_thai")
    private Integer trangThai;


}
