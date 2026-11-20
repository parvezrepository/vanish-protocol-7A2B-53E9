// IVanishManager.aidl
// Android Interface Definition Language (AIDL) for VANISH System Service
// Part of the Android Open Source Project (AOSP) VANISH Framework Patch

package com.android.server.vanish;

/**
 * System-level IPC interface for the VANISH Lifecycle Enforcement Service.
 * Allows system components (MediaProvider, DownloadManager, StorageManager)
 * and authorized system applications to register, query, and enforce .vfile policies.
 */
interface IVanishManager {

    /**
     * Register a newly downloaded or created .vfile container with the OS lifecycle manager.
     *
     * @param filePath Absolute path of the .vfile container on local storage.
     * @param fileUuid Unique UUIDv4 string assigned to the file manifest.
     * @param issuedAt Epoch timestamp (seconds) when the container was signed.
     * @param expiresAt Epoch timestamp (seconds) when the container must be purged.
     * @param policy Integer code corresponding to ExpiryPolicy (1=AUTO_UNLINK, 2=SECURE_SHRED, 3=REVOKE_KEY).
     * @param signature 64-byte Ed25519 digital signature extracted from the container.
     * @return true if the file was validated and successfully scheduled; false otherwise.
     */
    boolean registerContainer(
        in String filePath,
        in String fileUuid,
        long issuedAt,
        long expiresAt,
        int policy,
        in byte[] signature
    );

    /**
     * Query the remaining lifetime in seconds for a managed file.
     *
     * @param filePath Absolute path of the .vfile container.
     * @return Remaining lifetime in seconds; returns negative value if expired, -1 if untracked.
     */
    long getRemainingSeconds(in String filePath);

    /**
     * Check whether a specific container has satisfied its expiration condition.
     *
     * @param filePath Absolute path of the .vfile container.
     * @return true if the container is expired; false if currently active.
     */
    boolean isExpired(in String filePath);

    /**
     * Force immediate lifecycle enforcement (unlink or cryptographic shredding)
     * of an expired container. Restricted to system callers.
     *
     * @param filePath Absolute path of the .vfile container.
     * @param secureShred If true, overwrites disk blocks before unlinking.
     * @return true if deletion completed successfully.
     */
    boolean purgeContainer(in String filePath, boolean secureShred);

    /**
     * Query count of currently active time-bounded containers registered in the OS queue.
     */
    int getActiveContainerCount();
}
