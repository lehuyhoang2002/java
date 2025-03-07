package com.example.dreambackend.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VaiTroResponse {

    private Integer id;               // ID vai trò
    private String ten;               // Tên vai trò
    private Integer trangThai;         // Trạng thái (Active/Inactive)
}
