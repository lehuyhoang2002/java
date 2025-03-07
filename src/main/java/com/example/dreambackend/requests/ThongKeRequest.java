// Request DTO for ThongKe
package com.example.dreambackend.requests;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThongKeRequest {
    private String startDate;
    private String endDate;
}