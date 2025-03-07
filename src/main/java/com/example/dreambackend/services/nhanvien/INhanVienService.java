package com.example.dreambackend.services.nhanvien;

import com.example.dreambackend.entities.NhanVien;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface INhanVienService {
    // Hiển thị danh sách nhân viên có phân trang
    Page<NhanVien> getAllNhanVienPaged(int page, int size);

    // Thêm nhân viên mới
    NhanVien addNhanVien(NhanVien nhanVien);

    // Cập nhật nhân viên
    NhanVien updateNhanVien(NhanVien nhanVien);

    // Lấy chi tiết nhân viên theo id
    NhanVien getNhanVienById(Integer id);

    // Tìm kiếm nhân viên theo tên
    List<NhanVien> searchNhanVienByName(String ten);

    // Phương thức đăng nhập (trả về boolean)
    ResponseEntity<?> login(String email, String password);
}
