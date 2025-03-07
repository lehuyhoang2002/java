package com.example.dreambackend.services.vaitro;

import com.example.dreambackend.entities.VaiTro;

import java.util.List;

public interface IVaiTroService {
    List<VaiTro> getAllVaiTros(); // Hiển thị danh sách vai trò
    VaiTro addVaiTro(VaiTro vaiTro); // Thêm vai trò
    VaiTro updateVaiTro(VaiTro vaiTro); // Sửa vai trò
}
