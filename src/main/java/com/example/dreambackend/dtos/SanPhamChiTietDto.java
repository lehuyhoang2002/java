package com.example.dreambackend.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SanPhamChiTietDto {
    private Integer id;
    private String ma;
    private String sanPhamTen;
    private String mauSacTen;
    private String sizeTen;
    private Double gia;
    private int soLuong;
    private boolean isSelected;
    private boolean isDisabled;

}
