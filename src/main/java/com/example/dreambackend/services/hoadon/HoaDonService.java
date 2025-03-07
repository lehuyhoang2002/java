package com.example.dreambackend.services.hoadon;

import com.example.dreambackend.entities.*;
import com.example.dreambackend.repositories.*;
import com.example.dreambackend.requests.HoaDonRequest;
import com.example.dreambackend.responses.HoaDonResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class HoaDonService implements IHoaDonService {

    @Autowired
    private HoaDonRepository hoaDonRepository;
    @Autowired
    private KhachHangRepository khachHangRepository;
    @Autowired
    private NhanVienRepository nhanVienRepository;
    @Autowired
    private VoucherRepository voucherRepository;
    @Autowired
    private PhuongThucThanhToanRepository ptttRepository;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    @Override
    public HoaDonResponse updateHoaDon(Integer id, HoaDonRequest request) {
        HoaDon hoaDon = hoaDonRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Hóa đơn không tồn tại"));

        hoaDon.setTenNguoiNhan(request.getTenNguoiNhan());
        hoaDon.setSdtNguoiNhan(request.getSdtNguoiNhan());
        hoaDon.setDiaChiNhanHang(request.getDiaChiNhanHang());
        hoaDon.setPhiVanChuyen(request.getPhiVanChuyen());
        hoaDon.setNgaySua(LocalDate.now());

        if (request.getIdVoucher() != null) {
            Voucher voucher = voucherRepository.findById(request.getIdVoucher())
                    .orElseThrow(() -> new RuntimeException("Voucher không tồn tại"));
            hoaDon.setVoucher(voucher);
        }

        return convertToDTO(hoaDonRepository.save(hoaDon));
    }

    @Override
    public HoaDonResponse createHoaDon(HoaDonRequest request) {
        HoaDon hoaDon = convertToEntity(request);
        return convertToDTO(hoaDonRepository.save(hoaDon));
    }

//    @Override
//    public void deleteHoaDon(Integer id) {
//        HoaDon hoaDon = hoaDonRepository.findById(id)
//                .orElseThrow(() -> new RuntimeException("Hóa đơn không tồn tại"));
//        hoaDon.setTrangThai(0); // Đánh dấu đã xóa
//        hoaDon.setNgaySua(LocalDate.now());
//        hoaDonRepository.save(hoaDon);
//    }

    @Override
    public HoaDonResponse findById(Integer id) {
        HoaDon hoaDon = hoaDonRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy hóa đơn"));
        return convertToDTO(hoaDon);
    }

    @Override
    public List<HoaDonResponse> getAllHoaDon() {
        List<HoaDon> hoaDons = hoaDonRepository.findAllByTrangThai(1);
        return hoaDons.stream().map(this::convertToDTO).toList();
    }

    private HoaDon convertToEntity(HoaDonRequest request) {
        KhachHang khachHang = khachHangRepository.findById(request.getIdKhachHang())
                .orElseThrow(() -> new RuntimeException("Khách hàng không tồn tại"));
        NhanVien nhanVien = nhanVienRepository.findById(request.getIdNhanVien())
                .orElseThrow(() -> new RuntimeException("Nhân viên không tồn tại"));
        PhuongThucThanhToan pttt = ptttRepository.findById(request.getIdPhuongThucThanhToan())
                .orElseThrow(() -> new RuntimeException("Phương thức thanh toán không tồn tại"));

        Voucher voucher = null;
        if (request.getIdVoucher() != null) {
            voucher = voucherRepository.findById(request.getIdVoucher())
                    .orElseThrow(() -> new RuntimeException("Voucher không tồn tại"));
        }

        return HoaDon.builder()
                .ma(generateMaHoaDon())
                .khachHang(khachHang)
                .nhanVien(nhanVien)
                .phuongThucThanhToan(pttt)
                .voucher(voucher)
                .tenNguoiNhan(request.getTenNguoiNhan())
                .sdtNguoiNhan(request.getSdtNguoiNhan())
                .diaChiNhanHang(request.getDiaChiNhanHang())
                .hinhThucThanhToan(request.getHinhThucThanhToan())
                .phiVanChuyen(request.getPhiVanChuyen())
                .tongTienTruocVoucher(request.getTongTienTruocVoucher())
                .tongTienThanhToan(request.getTongTienThanhToan())
                .ngayNhanDuKien(parseDate(request.getNgayNhanDuKien()))
                .ngayTao(parseDate(request.getNgayTao()))
                .ngaySua(parseDate(request.getNgaySua()))
                .trangThai(request.getTrangThai() != null ? request.getTrangThai() : 1)
                .ghiChu(request.getGhiChu())
                .build();
    }

    private HoaDonResponse convertToDTO(HoaDon hoaDon) {
        return HoaDonResponse.builder()
                .id(hoaDon.getId())
                .idKhachHang(hoaDon.getKhachHang().getId())
                .idNhanVien(hoaDon.getNhanVien().getId())
                .idVoucher(hoaDon.getVoucher() != null ? hoaDon.getVoucher().getId() : null)
                .idPhuongThucThanhToan(hoaDon.getPhuongThucThanhToan().getId())
                .tenNguoiNhan(hoaDon.getTenNguoiNhan())
                .sdtNguoiNhan(hoaDon.getSdtNguoiNhan())
                .diaChiNhanHang(hoaDon.getDiaChiNhanHang())
                .hinhThucThanhToan(hoaDon.getHinhThucThanhToan())
                .phiVanChuyen(hoaDon.getPhiVanChuyen())
                .tongTienTruocVoucher(hoaDon.getTongTienTruocVoucher())
                .tongTienThanhToan(hoaDon.getTongTienThanhToan())
                .ngayNhanDuKien(hoaDon.getNgayNhanDuKien())
                .ngayTao(hoaDon.getNgayTao())
                .ngaySua(hoaDon.getNgaySua())
                .trangThai(hoaDon.getTrangThai())
                .ghiChu(hoaDon.getGhiChu())
                .build();
    }

    private LocalDate parseDate(String dateString) {
        return (dateString != null && !dateString.isEmpty()) ? LocalDate.parse(dateString, DATE_FORMATTER) : LocalDate.now();
    }

    private String generateMaHoaDon() {
            String ma;
            do {
                ma = "HD" + LocalDate.now().format(DateTimeFormatter.ofPattern("yyMMddHHmmss"));
            } while (hoaDonRepository.findByMa(ma).isPresent());
            return ma;
    }
}
