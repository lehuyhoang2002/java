package com.example.dreambackend.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AnhRespone {
    private Integer id;

    private String anhUrl;

    private LocalDate ngayTao;

    private LocalDate ngaySua;

    private int trangThai;

    private Integer idSanPham;
}
