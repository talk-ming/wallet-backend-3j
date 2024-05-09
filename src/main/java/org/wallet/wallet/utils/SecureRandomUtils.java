package org.wallet.wallet.utils;

import org.web3j.crypto.LinuxSecureRandom;

import java.security.SecureRandom;

public class SecureRandomUtils {
    private static final SecureRandom SECURE_RANDOM;
    private static int isAndroid;

    public static SecureRandom secureRandom() {
        return SECURE_RANDOM;
    }

    private static boolean isAndroidRuntime() {
        if (isAndroid == -1) {
            String runtime = System.getProperty("java.runtime.name");
            isAndroid = runtime != null && "Android Runtime".equals(runtime) ? 1 : 0;
        }

        return isAndroid == 1;
    }

    private SecureRandomUtils() {
    }

    static {
        if (isAndroidRuntime()) {
            new LinuxSecureRandom();
        }

        SECURE_RANDOM = new SecureRandom();
        isAndroid = -1;
    }
}
