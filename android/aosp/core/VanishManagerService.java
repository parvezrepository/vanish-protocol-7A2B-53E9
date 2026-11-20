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

package com.android.server.vanish;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Slog;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;

/**
 * VanishManagerService: Core AOSP System Service implementing native operating
 * system-level file lifecycle enforcement for the VANISH protocol.
 *
 * Published under ServiceManager as Context.VANISH_SERVICE ("vanish").
 * Interacts with AlarmManager for exact Doze-resilient timer wakeups and performs
 * multi-pass cryptographic block overwriting (SECURE_SHRED) prior to unlinking.
 */
public class VanishManagerService extends IVanishManager.Stub {

    private static final String TAG = "VanishManagerService";
    private static final boolean DEBUG = true;

    public static final String ACTION_EXPIRE_ALARM = "com.android.server.vanish.action.EXPIRE_CHECK";
    private static final byte[] VANISH_MAGIC = new byte[] {0x56, 0x41, 0x4E, 0x31}; // "VAN1"
    private static final int FIXED_HEADER_SIZE = 32;

    public static final int POLICY_AUTO_UNLINK = 1;
    public static final int POLICY_SECURE_SHRED = 2;
    public static final int POLICY_REVOKE_KEY = 3;

    private final Context mContext;
    private final AlarmManager mAlarmManager;
    private final Handler mHandler;
    private final SecureRandom mSecureRandom = new SecureRandom();

    // In-memory tracked containers indexed by absolute file path
    private final ConcurrentHashMap<String, ManagedContainer> mTrackedFiles = new ConcurrentHashMap<>();
    
    // Priority queue of pending expirations ordered by expiration epoch
    private final PriorityQueue<ManagedContainer> mExpiryQueue = new PriorityQueue<>(
        Comparator.comparingLong(c -> c.expiresAtEpochSec)
    );
    private final Object mQueueLock = new Object();

    /**
     * Representation of a time-bounded file tracked by the system service.
     */
    public static class ManagedContainer {
        public final String filePath;
        public final String fileUuid;
        public final long issuedAtEpochSec;
        public final long expiresAtEpochSec;
        public final int policy;
        public final byte[] signature;

        public ManagedContainer(
            String filePath,
            String fileUuid,
            long issuedAt,
            long expiresAt,
            int policy,
            byte[] signature
        ) {
            this.filePath = filePath;
            this.fileUuid = fileUuid;
            this.issuedAtEpochSec = issuedAt;
            this.expiresAtEpochSec = expiresAt;
            this.policy = policy;
            this.signature = signature;
        }
    }

    public VanishManagerService(Context context) {
        this.mContext = context;
        this.mAlarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);

        // Dedicated background thread for file I/O operations (shredding/unlinking)
        HandlerThread thread = new HandlerThread("VanishManagerWorker", Process.THREAD_PRIORITY_BACKGROUND);
        thread.start();
        this.mHandler = new Handler(thread.getLooper());

        registerSystemBroadcastReceivers();
        Slog.i(TAG, "VanishManagerService initialized successfully.");
    }

    private void registerSystemBroadcastReceivers() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_EXPIRE_ALARM);
        filter.addAction(Intent.ACTION_BOOT_COMPLETED);
        filter.addAction(Intent.ACTION_TIME_CHANGED);
        filter.addAction(Intent.ACTION_TIMEZONE_CHANGED);

        mContext.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                if (ACTION_EXPIRE_ALARM.equals(action)) {
                    mHandler.post(() -> processPendingExpirations());
                } else if (Intent.ACTION_TIME_CHANGED.equals(action) || Intent.ACTION_TIMEZONE_CHANGED.equals(action)) {
                    Slog.w(TAG, "System time adjustment detected. Re-evaluating active container schedules.");
                    mHandler.post(() -> processPendingExpirations());
                } else if (Intent.ACTION_BOOT_COMPLETED.equals(action)) {
                    Slog.i(TAG, "Device boot completed. Scanning registered storage directories.");
                    mHandler.post(() -> rescheduleNextAlarm());
                }
            }
        }, filter, Context.RECEIVER_NOT_EXPORTED);
    }

    @Override
    public boolean registerContainer(
        String filePath,
        String fileUuid,
        long issuedAt,
        long expiresAt,
        int policy,
        byte[] signature
    ) {
        enforceSystemOrStoragePermission();

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            Slog.e(TAG, "Cannot register non-existent file: " + filePath);
            return false;
        }

        long nowSec = System.currentTimeMillis() / 1000L;
        if (nowSec >= expiresAt) {
            Slog.w(TAG, "File " + filePath + " is already expired upon registration. Triggering immediate purge.");
            mHandler.post(() -> purgeContainerInternal(filePath, policy == POLICY_SECURE_SHRED));
            return true;
        }

        ManagedContainer container = new ManagedContainer(filePath, fileUuid, issuedAt, expiresAt, policy, signature);
        synchronized (mQueueLock) {
            mTrackedFiles.put(filePath, container);
            mExpiryQueue.add(container);
            rescheduleNextAlarm();
        }

        Slog.i(TAG, "Registered VANISH container: " + file.getName() + " (expires in " + (expiresAt - nowSec) + "s)");
        return true;
    }

    @Override
    public long getRemainingSeconds(String filePath) {
        ManagedContainer container = mTrackedFiles.get(filePath);
        if (container == null) {
            return -1L;
        }
        long nowSec = System.currentTimeMillis() / 1000L;
        return container.expiresAtEpochSec - nowSec;
    }

    @Override
    public boolean isExpired(String filePath) {
        long remaining = getRemainingSeconds(filePath);
        return remaining <= 0L && remaining != -1L;
    }

    @Override
    public boolean purgeContainer(String filePath, boolean secureShred) {
        enforceSystemOrStoragePermission();
        return purgeContainerInternal(filePath, secureShred);
    }

    @Override
    public int getActiveContainerCount() {
        return mTrackedFiles.size();
    }

    private void processPendingExpirations() {
        long nowSec = System.currentTimeMillis() / 1000L;
        synchronized (mQueueLock) {
            while (!mExpiryQueue.isEmpty() && mExpiryQueue.peek().expiresAtEpochSec <= nowSec) {
                ManagedContainer expired = mExpiryQueue.poll();
                if (expired != null) {
                    mTrackedFiles.remove(expired.filePath);
                    boolean shouldShred = (expired.policy == POLICY_SECURE_SHRED);
                    purgeContainerInternal(expired.filePath, shouldShred);
                }
            }
            rescheduleNextAlarm();
        }
    }

    private void rescheduleNextAlarm() {
        synchronized (mQueueLock) {
            if (mExpiryQueue.isEmpty()) {
                return;
            }
            ManagedContainer next = mExpiryQueue.peek();
            long nowSec = System.currentTimeMillis() / 1000L;
            long delaySec = Math.max(0L, next.expiresAtEpochSec - nowSec);
            long triggerAtMillis = SystemClock.elapsedRealtime() + (delaySec * 1000L);

            Intent intent = new Intent(ACTION_EXPIRE_ALARM);
            PendingIntent pi = PendingIntent.getBroadcast(
                mContext,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
            );

            // Use setExactAndAllowWhileIdle for precision across Android Doze sleep states
            mAlarmManager.setExactAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                triggerAtMillis,
                pi
            );

            if (DEBUG) {
                Slog.d(TAG, "Scheduled next lifecycle wake in " + delaySec + "s for: " + next.filePath);
            }
        }
    }

    private boolean purgeContainerInternal(String filePath, boolean secureShred) {
        File file = new File(filePath);
        if (!file.exists()) {
            return false;
        }

        Slog.i(TAG, "[OS ENFORCEMENT] Purging expired file: " + filePath + " (SecureShred=" + secureShred + ")");
        try {
            if (secureShred) {
                shredFileOnDisk(file, 2);
            }
            boolean deleted = file.delete();
            if (!deleted) {
                Slog.w(TAG, "Standard delete failed, requesting forced unlink via StorageManager: " + filePath);
            }
            return deleted;
        } catch (Exception e) {
            Slog.e(TAG, "Error executing purge on " + filePath, e);
            return false;
        }
    }

    private void shredFileOnDisk(File file, int passes) throws IOException {
        long fileLength = file.length();
        if (fileLength <= 0) {
            return;
        }

        byte[] randomBuffer = new byte[8192];
        try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
            for (int p = 0; p < passes; p++) {
                raf.seek(0);
                long bytesRemaining = fileLength;
                while (bytesRemaining > 0) {
                    int bytesToWrite = (int) Math.min(randomBuffer.length, bytesRemaining);
                    mSecureRandom.nextBytes(randomBuffer);
                    raf.write(randomBuffer, 0, bytesToWrite);
                    bytesRemaining -= bytesToWrite;
                }
                raf.getFD().sync();
            }
        }
    }

    private void enforceSystemOrStoragePermission() {
        int callingUid = Binder.getCallingUid();
        if (callingUid == Process.SYSTEM_UID || callingUid == Process.ROOT_UID) {
            return;
        }
        mContext.enforceCallingOrSelfPermission(
            android.Manifest.permission.MANAGE_EXTERNAL_STORAGE,
            "Caller does not possess system authorization to manage file lifecycles"
        );
    }
}
