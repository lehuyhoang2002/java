package com.example.dreambackend.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ThongKeThangNayResponse {
    private int ngay;
    private double tongDoanhThu; // Tổng doanh thu của ngày đó
}




