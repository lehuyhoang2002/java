package com.example.dreambackend.services.khachhang;

import com.example.dreambackend.dtos.KhachHangDto;
import com.example.dreambackend.entities.KhachHang;
import com.example.dreambackend.entities.Voucher;
import com.example.dreambackend.repositories.KhachHangRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
public class KhachHangService implements IKhachHangService{
    @Autowired
    private KhachHangRepository khachHangRepository;

    @Override
    public Page<KhachHang> getAllKhachHangPaged(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<KhachHang> khachhangs = khachHangRepository.findAll(pageable);

        return khachhangs;
    }

    @Override
    public KhachHang getKhachHangById(Integer id) {
        return khachHangRepository.findById(id).orElseThrow(()
                -> new RuntimeException("Không tim được id cua khach hang"));
    }
    @Override
    public KhachHang addKhachHang(KhachHangDto khachHangDto) {
        KhachHang newKhachHang = KhachHang.builder()
                .ma("test")
                .ten(khachHangDto.getTen())
                .gioiTinh(khachHangDto.isGioiTinh())
                .soDienThoai(khachHangDto.getSoDienThoai())
                .matKhau(khachHangDto.getMatKhau())
                .ngayTao(LocalDate.now())
                .trangThai(1)
                .build();
        return  khachHangRepository.save(newKhachHang);


    }




    @Override
    public KhachHang updateKhachHang(KhachHang khachHang) {
        khachHang.setNgaySua(LocalDate.now());
        return khachHangRepository.save(khachHang);
    }

    @Override
    public List<KhachHang> searchKhachHangByName(String ten) {
        return khachHangRepository.findByTenContainingIgnoreCase(ten);
    }

    @Override
    public KhachHang getKhachHangBySoDienThoai(String soDienThoai) {
        return khachHangRepository.findKhachHangBySoDienThoai(soDienThoai);
    }
}