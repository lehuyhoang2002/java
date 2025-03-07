package com.example.dreambackend.services.giohangchitiet;

import com.example.dreambackend.entities.GioHangChiTiet;
import com.example.dreambackend.entities.KhachHang;
import com.example.dreambackend.entities.SanPhamChiTiet;
import com.example.dreambackend.repositories.GioHangChiTietRepository;
import com.example.dreambackend.repositories.KhachHangRepository;
import com.example.dreambackend.repositories.SanPhamChiTietRepository;
import com.example.dreambackend.requests.GioHangChiTietRequest;
import com.example.dreambackend.responses.GioHangChiTietResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class GioHangChiTietService implements IGioHangChiTietService {

    @Autowired
    private GioHangChiTietRepository ghctRepository;

    @Autowired
    private KhachHangRepository khachHangRepository;

    @Autowired
    private SanPhamChiTietRepository spctRepository;

    @Override
    public GioHangChiTietResponse addToGioHang(Integer khachHangId, GioHangChiTietRequest request) {
        KhachHang khachHang = khachHangRepository.findById(khachHangId)
                .orElseThrow(() -> new RuntimeException("Khách hàng không tồn tại"));
        SanPhamChiTiet sanPhamChiTiet = spctRepository.findById(request.getIdSanPhamChiTiet())
                .orElseThrow(() -> new RuntimeException("Sản phẩm chi tiết không tồn tại"));

        List<GioHangChiTiet> existingItems = ghctRepository.findByKhachHangAndSanPhamChiTiet(khachHang, sanPhamChiTiet);

        GioHangChiTiet savedItem;
        if (!existingItems.isEmpty()) {
            // Tổng hợp số lượng của tất cả mục giỏ hàng trùng nhau
            int totalSoLuong = existingItems.stream().mapToInt(GioHangChiTiet::getSoLuong).sum() + request.getSoLuong();

            // Xóa tất cả mục cũ
            ghctRepository.deleteAll(existingItems);

            // Tạo một mục mới với số lượng đã cộng dồn
            GioHangChiTiet newItem = convertToEntity(request, khachHang, sanPhamChiTiet);
            newItem.setSoLuong(totalSoLuong); // Gán tổng số lượng mới
            savedItem = ghctRepository.save(newItem);
        } else {
            GioHangChiTiet newItem = convertToEntity(request, khachHang, sanPhamChiTiet);
            savedItem = ghctRepository.save(newItem);
        }

        return convertToDTO(savedItem);
    }

    @Override
    public GioHangChiTietResponse updateSoLuong(Integer id, Integer soLuong) {
        GioHangChiTiet item = ghctRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Mục giỏ hàng không tồn tại"));

        if (soLuong <= 0) {
            throw new RuntimeException("Số lượng phải lớn hơn 0");
        }

        item.setSoLuong(soLuong);
        item.setNgaySua(LocalDate.now());
        return convertToDTO(ghctRepository.save(item));
    }

    @Override
    public void removeFromGioHang(Integer id) {
        GioHangChiTiet item = ghctRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Mục giỏ hàng không tồn tại"));
        item.setTrangThai(0);
        item.setNgaySua(LocalDate.now());
        ghctRepository.save(item);
    }

    @Override
    public List<GioHangChiTietResponse> getGioHangByKhachHang(Integer khachHangId) {
        KhachHang khachHang = khachHangRepository.findById(khachHangId)
                .orElseThrow(() -> new RuntimeException("Khách hàng không tồn tại"));
        return ghctRepository.findByKhachHang(khachHang)
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public void clearGioHang(Integer khachHangId) {
        KhachHang khachHang = khachHangRepository.findById(khachHangId)
                .orElseThrow(() -> new RuntimeException("Khách hàng không tồn tại"));

        ghctRepository.findByKhachHang(khachHang).forEach(item -> {
            item.setTrangThai(0);
            item.setNgaySua(LocalDate.now());
        });

        ghctRepository.saveAll(ghctRepository.findByKhachHang(khachHang));
    }

    private GioHangChiTietResponse convertToDTO(GioHangChiTiet entity) {
        return GioHangChiTietResponse.builder()
                .id(entity.getId())
                .soLuong(entity.getSoLuong())
                .donGia(entity.getDonGia() != null ? entity.getDonGia() : 0.0)
                .ngayTao(entity.getNgayTao())
                .ngaySua(entity.getNgaySua())
                .trangThai(entity.getTrangThai())
                .idKhachHang(entity.getKhachHang().getId())
                .idSanPhamChiTiet(entity.getSanPhamChiTiet().getId())
                .build();
    }

    private GioHangChiTiet convertToEntity(GioHangChiTietRequest request, KhachHang khachHang, SanPhamChiTiet sanPhamChiTiet) {
        return GioHangChiTiet.builder()
                .khachHang(khachHang)
                .sanPhamChiTiet(sanPhamChiTiet)
                .soLuong(request.getSoLuong())
                .donGia(sanPhamChiTiet.getGia() != null ? sanPhamChiTiet.getGia() : 0.0) // Tránh null giá
                .ngayTao(LocalDate.now())
                .ngaySua(LocalDate.now())
                .trangThai(1)
                .build();
    }
}
