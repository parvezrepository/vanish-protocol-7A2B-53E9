# VANISH: Android Open Source Project (AOSP) Native Integration

This directory contains the reference AOSP framework patch files for integrating the **VANISH Universal File Lifecycle Protocol** natively into Android 14+ (UpsideDownCake / VanillaIceCream).

---

## Architecture Overview

```
+-----------------------------------------------------------------------------+
|                               Android SystemUI                              |
|           (Files by Google, Samsung My Files, System Share Sheet)           |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|            Storage Access Framework: VanishDocumentsProvider.java           |
|            - Exposes virtual "VANISH Ephemeral Storage" to user             |
|            - Displays countdown badges and filters expired documents        |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|           MediaProvider Hook: VanishMediaScannerHook.java                   |
|           - Intercepts incoming downloads in DownloadManager                |
|           - Ingests 32-byte binary header & extracts CBOR manifest          |
+-----------------------------------------------------------------------------+
                                       | (AIDL IPC)
                                       v
+-----------------------------------------------------------------------------+
|             System Server: VanishManagerService.java                        |
|             - Registered as Context.VANISH_SERVICE in ServiceManager        |
|             - Priority queue (heap) tracking upcoming expirations            |
|             - AlarmManager.setExactAndAllowWhileIdle (Doze-resilient)       |
|             - Multi-pass cryptographic block overwriting (SECURE_SHRED)     |
+-----------------------------------------------------------------------------+
```

---

## File Directory

- `aosp/core/IVanishManager.aidl`: Android Interface Definition Language contract defining inter-process communication with the system daemon.
- `aosp/core/VanishManagerService.java`: Full AOSP system service running inside `system_server`. Manages exact alarms, in-memory queues, and cryptographic file shredding.
- `aosp/provider/VanishMediaScannerHook.java`: Injected listener into AOSP `ModernMediaScanner` to detect `.vfile` creation in real time.
- `aosp/saf/VanishDocumentsProvider.java`: Storage Access Framework integration providing transparent file management without a dedicated user app.
- `sepolicy/vanish.te`: SELinux security rules enforcing least-privilege lifecycle management.

---

## Integration Steps for AOSP Build Trees

1. **Copy Service & AIDL:**
   ```bash
   cp aosp/core/IVanishManager.aidl $AOSP_ROOT/frameworks/base/core/java/com/android/server/vanish/
   cp aosp/core/VanishManagerService.java $AOSP_ROOT/frameworks/base/services/core/java/com/android/server/vanish/
   ```

2. **Register in `SystemServer.java`:**
   In `$AOSP_ROOT/frameworks/base/services/java/com/android/server/SystemServer.java`:
   ```java
   t.traceBegin("StartVanishManagerService");
   mSystemServiceManager.startService(VanishManagerService.class);
   t.traceEnd();
   ```

3. **Apply SELinux Policies:**
   ```bash
   cat sepolicy/vanish.te >> $AOSP_ROOT/system/sepolicy/private/vanish.te
   ```

4. **Build and Flash:**
   ```bash
   source build/envsetup.sh
   lunch aosp_arm64-userdebug
   m services
   ```
