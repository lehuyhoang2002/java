package com.example.dreambackend.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ThongKeHomNayResponse {
    private long soHoaDon;         // Số hóa đơn trong ngày hôm nay
    private double tongDoanhThu;   // Tổng doanh thu trong ngày hôm nay
    private long soKhachHang;      // Số khách hàng trong ngày hôm nay
}
