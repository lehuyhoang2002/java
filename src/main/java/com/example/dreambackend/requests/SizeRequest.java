package com.example.dreambackend.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Range;

import java.time.LocalDate;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SizeRequest {
    private Integer id;

    private String ma;

    @NotBlank(message = "Size không được để trống")
    @Pattern(regexp = "XS|S|M|L|XL|XXL|XXXL", message = "Size phải là XS, S, M, L, XL, XXL, XXXL")
    private String ten;

    private LocalDate ngayTao;

    private LocalDate ngaySua;

    @Range(min = 0, max = 1, message = "Vui lòng chọn trạng thái")
    private int trangThai;
}
