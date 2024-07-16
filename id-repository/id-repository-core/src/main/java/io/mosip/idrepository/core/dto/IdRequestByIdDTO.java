package io.mosip.idrepository.core.dto;

import lombok.Data;

@Data
public class IdRequestByIdDTO {
	private String id;
	private String type;
	private String idType;
	private String fingerExtractionFormat;
	private String irisExtractionFormat;
	private String faceExtractionFormat;
}
