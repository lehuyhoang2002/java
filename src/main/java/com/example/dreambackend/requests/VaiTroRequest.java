package com.example.dreambackend.requests;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VaiTroRequest {
    private Integer id;               // ID vai trò (bắt buộc khi Update, không cần khi Create)
    private String ten;               // Tên vai trò
    private Integer trangThai;         // Trạng thái (Active/Inactive)
}
