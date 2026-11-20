/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.providers.media.scan;

import android.content.Context;
import android.os.IBinder;
import android.os.ServiceManager;
import android.util.Slog;

import com.android.server.vanish.IVanishManager;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * VanishMediaScannerHook: Injected hook for AOSP ModernMediaScanner.
 * Intercepts newly indexed media items on Android storage volumes.
 * When a file with extension .vfile is detected, parses the 32-byte header,
 * extracts manifest bounds, and registers the file with VanishManagerService.
 */
public class VanishMediaScannerHook {

    private static final String TAG = "VanishMediaScannerHook";
    private static final byte[] EXPECTED_MAGIC = new byte[] {0x56, 0x41, 0x4E, 0x31}; // "VAN1"
    private static final int HEADER_SIZE = 32;

    private static IVanishManager sVanishService = null;

    private static synchronized IVanishManager getVanishService() {
        if (sVanishService == null) {
            IBinder binder = ServiceManager.getService("vanish");
            if (binder != null) {
                sVanishService = IVanishManager.Stub.asInterface(binder);
            }
        }
        return sVanishService;
    }

    /**
     * Called by ModernMediaScanner when scanning a new or updated file.
     *
     * @param context Host application context.
     * @param file Target file scanned by MediaProvider.
     * @param mimeType Resolved MIME type.
     */
    public static void onScanFile(Context context, File file, String mimeType) {
        if (file == null || !file.getName().endsWith(".vfile")) {
            return;
        }

        Slog.i(TAG, "Inspecting incoming container: " + file.getAbsolutePath());

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] headerBytes = new byte[HEADER_SIZE];
            int read = fis.read(headerBytes);
            if (read < HEADER_SIZE) {
                Slog.w(TAG, "File too small to contain valid VANISH header: " + file.getName());
                return;
            }

            ByteBuffer buffer = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN);
            byte[] magic = new byte[4];
            buffer.get(magic);
            if (!Arrays.equals(magic, EXPECTED_MAGIC)) {
                Slog.w(TAG, "Invalid magic bytes in .vfile: " + file.getName());
                return;
            }

            int version = buffer.getShort() & 0xFFFF;
            int flags = buffer.getShort() & 0xFFFF;
            long manifestLen = buffer.getInt() & 0xFFFFFFFFL;
            long payloadLen = buffer.getLong();
            int sigLen = buffer.getShort() & 0xFFFF;
            int pubkeyLen = buffer.getShort() & 0xFFFF;
            int nonceLen = buffer.getShort() & 0xFFFF;

            // Skip pubkey and nonce to read signature
            fis.skip(pubkeyLen + nonceLen);
            byte[] signature = new byte[sigLen];
            fis.read(signature);

            // Read raw CBOR manifest
            byte[] manifestBytes = new byte[(int) manifestLen];
            fis.read(manifestBytes);

            // Forward registration to VanishManagerService via AIDL IPC
            IVanishManager service = getVanishService();
            if (service != null) {
                // For demonstrative AOSP integration: Extract default policy and timestamps
                long nowSec = System.currentTimeMillis() / 1000L;
                long defaultTtl = 86400L; // Fallback 24h
                int policy = (flags & 0x0004) != 0 ? 2 : 1; // 2 = SECURE_SHRED, 1 = AUTO_UNLINK

                boolean registered = service.registerContainer(
                    file.getAbsolutePath(),
                    file.getName(),
                    nowSec,
                    nowSec + defaultTtl,
                    policy,
                    signature
                );
                Slog.i(TAG, "Container registration status for " + file.getName() + ": " + registered);
            } else {
                Slog.e(TAG, "VanishManagerService unavailable in ServiceManager");
            }

        } catch (Exception e) {
            Slog.e(TAG, "Failed to inspect container: " + file.getAbsolutePath(), e);
        }
    }
}
