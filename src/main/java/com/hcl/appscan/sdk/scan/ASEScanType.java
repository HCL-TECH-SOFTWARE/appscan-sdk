package com.hcl.appscan.sdk.scan;

public enum ASEScanType {
    FULL_SCAN("Full Scan", "1"),
    TEST_ONLY("Test Only", "3"),
    POSTMAN_COLLECTION("Postman Collection", "4");

    private final String type;
    private final String code;

    ASEScanType(String type, String code) {
        this.type = type;
        this.code = code;
    }

    public String getType() {
        return type;
    }

    public String getCode() {
        return code;
    }

    public static String scanTypeCode(String type) {
        for (ASEScanType scanType : values()) {
            if (scanType.getType().equalsIgnoreCase(type)) {
                return scanType.getCode();
            }
        }
        return type; // fallback for unknown type
    }

    public static String scanTypeName(String code) {
        for (ASEScanType scanType : values()) {
            if (scanType.getCode().equals(code)) {
                return scanType.getType();
            }
        }
        return ""; // fallback for unknown code
    }
}
