package com.awslabs.iatt.spe.serverless.gwt.shared;

public class Helpers {
    // We don't use real hex here because we're just trying to make something look like an ICCID
    private static final char[] FAKE_HEX_ARRAY = "0123456789123456".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = FAKE_HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = FAKE_HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
