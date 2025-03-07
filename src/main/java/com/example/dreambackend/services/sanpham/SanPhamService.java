package com.example.dreambackend.services.sanpham;

import com.example.dreambackend.entities.*;
import com.example.dreambackend.repositories.*;
import com.example.dreambackend.requests.SanPhamRequest;
import com.example.dreambackend.responses.SanPhamRespone;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDate;
import java.util.List;
import java.util.Random;

@Service
public class SanPhamService implements ISanPhamService {
    @Autowired
    SanPhamRepository sanPhamRepository;
    @Autowired
    ThuongHieuRepository thuongHieuRepository;
    @Autowired
    XuatXuRepository xuatXuRepository;
    @Autowired
    CoAoRepository coAoRepository;
    @Autowired
    ChatLieuRepository chatLieuRepository;
    @Override
    public Page<SanPhamRespone> getAllSanPham(Pageable pageable) {
        return sanPhamRepository.getAllSanPhamRepone(pageable);
    }

    @Override
    public SanPham addSanPham(SanPhamRequest sanPhamRequest) {
        SanPham sanPham = new SanPham();
        // Copy các thuộc tính cơ bản từ request sang entity
        BeanUtils.copyProperties(sanPhamRequest, sanPham);
        sanPham.setMa(taoMaSanPham());
        // Set ngày tạo và ngày sửa
        sanPham.setNgayTao(LocalDate.now());
        sanPham.setNgaySua(LocalDate.now());
        // Lưu sản phẩm
        return sanPhamRepository.save(sanPham);
    }

    public boolean existsTenSanPham(String ten){
        return sanPhamRepository.existsByTen(ten);
    }

    private String taoMaSanPham() {
        Random random = new Random();
        String maSanPham;
        do {
            int soNgauNhien = 1 + random.nextInt(9999); // Sinh số từ 1 đến 9999
            String maSo = String.format("%04d", soNgauNhien); // Định dạng thành 4 chữ số
            maSanPham = "SP" + maSo;
        } while (sanPhamRepository.existsByMa(maSanPham)); // Kiểm tra xem mã đã tồn tại chưa
        return maSanPham;
    }


    @Override
    public SanPham updateSanPham(SanPhamRequest sanPhamRequest) {
        SanPham sanPhamUpdate = sanPhamRepository.findById(sanPhamRequest.getId()).orElseThrow(()->
                new RuntimeException("Không tìm thấy sản phẩm với id: " + sanPhamRequest.getId()));
        BeanUtils.copyProperties(sanPhamRequest, sanPhamUpdate,"id","ngayTao");
        sanPhamUpdate.setNgaySua(LocalDate.now());
        return sanPhamRepository.save(sanPhamUpdate);
    }

    @Override
    public SanPham getSanPhamById(Integer id) {
        return sanPhamRepository.findById(id).orElseThrow(()->
                new RuntimeException("Không tìm thấy id sản phẩm"));
    }

    public Page<SanPhamRespone> searchSanPham(
            Integer thuongHieuId, Integer xuatXuId, Integer chatLieuId, Integer coAoId, Integer trangThai, String ten, Pageable pageable) {
        return sanPhamRepository.searchSanPham(thuongHieuId, xuatXuId, chatLieuId, coAoId, trangThai, ten, pageable);
    }

    @Override
    public ResponseEntity<byte[]> exportSanPhamToExcel(List<SanPhamRespone> sanPhams) {
        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("Sản Phẩm");
            Row headerRow = sheet.createRow(0);
            String[] headers = {"Mã", "Tên", "Ngày Tạo", "Ngày Sửa", "Trạng Thái", "Thương Hiệu", "Chất Liệu", "Cổ Áo", "Xuất Xứ"};

            for (int i = 0; i < headers.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(headers[i]);
            }

            int rowNum = 1;
            for (SanPhamRespone sp : sanPhams) {
                Row row = sheet.createRow(rowNum++);
                row.createCell(0).setCellValue(sp.getMa());
                row.createCell(1).setCellValue(sp.getTen());
                row.createCell(2).setCellValue(sp.getNgayTao().toString());
                row.createCell(3).setCellValue(sp.getNgaySua().toString());
                row.createCell(4).setCellValue(sp.getTrangThai());
                row.createCell(5).setCellValue(sp.getTenThuongHieu());
                row.createCell(6).setCellValue(sp.getTenChatLieu());
                row.createCell(7).setCellValue(sp.getTenCoAo());
                row.createCell(8).setCellValue(sp.getTenXuatXu());
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            workbook.write(outputStream);
            HttpHeaders headersResponse = new HttpHeaders();
            headersResponse.add("Content-Disposition", "attachment; filename=sanpham.xlsx");
            return new ResponseEntity<>(outputStream.toByteArray(), headersResponse, HttpStatus.OK);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
