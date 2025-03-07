package com.example.dreambackend.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "san_pham_chi_tiet")
public class SanPhamChiTiet {
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "ma")
    private String ma;

    @Column(name = "gia")
    private Double gia;

    @Column(name = "so_luong")
    private int soLuong;

    @Column(name = "ngay_tao")
    private LocalDate ngayTao;

    @Column(name = "ngay_sua")
    private LocalDate ngaySua;

    @Column(name = "trang_thai")
    private int trangThai;

    @ManyToOne
    @JoinColumn(name = "id_san_pham",referencedColumnName = "id")
    private SanPham sanPham;

    @ManyToOne
    @JoinColumn(name = "id_size",referencedColumnName = "id")
    private Size size;

    @ManyToOne
    @JoinColumn(name = "id_mau_sac",referencedColumnName = "id")
    private MauSac mauSac;

    @ManyToOne
    @JoinColumn(name = "id_khuyen_mai",referencedColumnName = "id")
    private KhuyenMai khuyenMai;
}