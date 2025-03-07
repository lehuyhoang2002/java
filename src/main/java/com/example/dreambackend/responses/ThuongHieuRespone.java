package com.example.dreambackend.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ThuongHieuRespone {
    private Integer id;

    private String ma;

    private String ten;

    private LocalDate ngayTao;

    private LocalDate ngaySua;

    private int trangThai;
}
