package com.example.dreambackend.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SanPhamDto {
    private Integer id;
    private String ten;
    private Double gia;
    private String anhUrl;
}
