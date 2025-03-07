package com.example.dreambackend.services.nhanvien;

import com.example.dreambackend.entities.NhanVien;
import com.example.dreambackend.entities.VaiTro;
import com.example.dreambackend.repositories.NhanVienRepository;
import com.example.dreambackend.repositories.VaiTroRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class NhanVienService implements INhanVienService {

    @Autowired
    private NhanVienRepository nhanVienRepository;
    @Autowired
    private VaiTroRepository vaiTroRepository;
    @Autowired
    private PasswordEncoder passwordEncoder; // Inject PasswordEncoder

    @Transactional
    @Override
    public Page<NhanVien> getAllNhanVienPaged(int page, int size) {
        return nhanVienRepository.findAll(PageRequest.of(page, size));
    }

    @Override
    @Transactional
    public NhanVien addNhanVien(NhanVien nhanVien) {
        VaiTro vaiTro = vaiTroRepository.findById(nhanVien.getVaiTro().getId())
                .orElseThrow(() -> new IllegalArgumentException("Vai trò không tồn tại!"));

        // 🔹 Gán vai trò cho nhân viên
        nhanVien.setVaiTro(vaiTro);
        // Gán ngày tạo hiện tại
        nhanVien.setNgayTao(LocalDate.now());

        // 🔹 Mã hóa mật khẩu trước khi lưu
        String encodedPassword = passwordEncoder.encode(nhanVien.getMatKhau());
        nhanVien.setMatKhau(encodedPassword);
        return nhanVienRepository.save(nhanVien);
    }

    @Override
    @Transactional
    public NhanVien updateNhanVien(NhanVien nhanVien) {
        // 🔹 Kiểm tra nhân viên có tồn tại không
        NhanVien existingNhanVien = nhanVienRepository.findById(nhanVien.getId())
                .orElseThrow(() -> new IllegalArgumentException("Nhân viên không tồn tại!"));

        // 🔹 Kiểm tra vai trò có tồn tại không
        VaiTro vaiTro = vaiTroRepository.findById(nhanVien.getVaiTro().getId())
                .orElseThrow(() -> new IllegalArgumentException("Vai trò không tồn tại!"));

        // 🔹 Cập nhật thông tin nhân viên
        existingNhanVien.setTen(nhanVien.getTen());
        existingNhanVien.setGioiTinh(nhanVien.getGioiTinh());
        existingNhanVien.setNgaySinh(nhanVien.getNgaySinh());
        existingNhanVien.setEmail(nhanVien.getEmail());
        existingNhanVien.setSoDienThoai(nhanVien.getSoDienThoai());
        existingNhanVien.setTaiKhoan(nhanVien.getTaiKhoan());
        existingNhanVien.setMatKhau(nhanVien.getMatKhau());
        existingNhanVien.setTrangThai(nhanVien.getTrangThai());
        existingNhanVien.setNgaySua(LocalDate.now());

        // 🔹 Gán vai trò mới
        existingNhanVien.setVaiTro(vaiTro);

        return nhanVienRepository.save(existingNhanVien);
    }


    @Override
    public NhanVien getNhanVienById(Integer id) {
        return nhanVienRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Nhân viên không tồn tại với id: " + id));
    }

    @Override
    public List<NhanVien> searchNhanVienByName(String ten) {
        return nhanVienRepository.findByTenContainingIgnoreCase(ten);
    }

    // Phương thức kiểm tra đăng nhập
    @Override
    public ResponseEntity<?> login(String email, String password) {
        // Kiểm tra xem nhân viên có tồn tại không
        Optional<NhanVien> nhanVienOptional = nhanVienRepository.findByEmail(email);

        if (nhanVienOptional.isPresent()) {
            NhanVien nhanVien = nhanVienOptional.get();

            // Kiểm tra mật khẩu
            if (password.equals(nhanVien.getMatKhau())) {
                // Đăng nhập thành công, trả về thông tin nhân viên
                return ResponseEntity.ok(nhanVien); // Trả về thông tin nhân viên nếu đăng nhập thành công
            } else {
                // Mật khẩu không đúng
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Sai mật khẩu."); // Trả về lỗi với mã HTTP 401 (Unauthorized)
            }
        } else {
            // Không tìm thấy nhân viên với email này
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Email không tồn tại: "); // Trả về lỗi với mã HTTP 404 (Not Found)
        }
    }

}
