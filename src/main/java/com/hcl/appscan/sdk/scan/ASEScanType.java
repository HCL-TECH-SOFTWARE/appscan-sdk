/**
 * © Copyright HCL Technologies Ltd. 2025.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scan;

import com.hcl.appscan.sdk.CoreConstants;

public enum ASEScanType {
    FULL_SCAN(CoreConstants.FULL_SCAN, "1"),
    TEST_ONLY(CoreConstants.TEST_ONLY, "3"),
    POSTMAN_COLLECTION(CoreConstants.POSTMAN_COLLECTION, "4");

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
