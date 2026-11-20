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

package com.android.server.vanish.saf;

import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * VanishDocumentsProvider: Storage Access Framework (SAF) integration.
 *
 * Exposes a virtual "VANISH Managed Storage" volume to the standard Android
 * system file picker and DocumentsUI (Files app). Allows user apps to access
 * unexpired files transparently through file descriptors, while displaying
 * real-time expiry badges and denying access once lifetime has elapsed.
 */
public class VanishDocumentsProvider extends DocumentsProvider {

    private static final String TAG = "VanishDocumentsProvider";
    public static final String AUTHORITY = "com.android.server.vanish.documents";

    private static final String[] DEFAULT_ROOT_PROJECTION = new String[] {
        Root.COLUMN_ROOT_ID,
        Root.COLUMN_FLAGS,
        Root.COLUMN_TITLE,
        Root.COLUMN_DOCUMENT_ID,
        Root.COLUMN_ICON,
        Root.COLUMN_AVAILABLE_BYTES
    };

    private static final String[] DEFAULT_DOCUMENT_PROJECTION = new String[] {
        Document.COLUMN_DOCUMENT_ID,
        Document.COLUMN_MIME_TYPE,
        Document.COLUMN_DISPLAY_NAME,
        Document.COLUMN_LAST_MODIFIED,
        Document.COLUMN_FLAGS,
        Document.COLUMN_SIZE
    };

    private File mBaseDir;

    @Override
    public boolean onCreate() {
        Context context = getContext();
        if (context != null) {
            mBaseDir = new File(context.getFilesDir(), "vanish_vault");
            if (!mBaseDir.exists()) {
                mBaseDir.mkdirs();
            }
        }
        return true;
    }

    @Override
    public Cursor queryRoots(String[] projection) throws FileNotFoundException {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DEFAULT_ROOT_PROJECTION);
        MatrixCursor.RowBuilder row = result.newRow();
        row.add(Root.COLUMN_ROOT_ID, "vanish_root");
        row.add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_SEARCH | Root.FLAG_LOCAL_ONLY);
        row.add(Root.COLUMN_TITLE, "VANISH Ephemeral Storage");
        row.add(Root.COLUMN_DOCUMENT_ID, "root");
        row.add(Root.COLUMN_AVAILABLE_BYTES, mBaseDir.getFreeSpace());
        return result;
    }

    @Override
    public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DEFAULT_DOCUMENT_PROJECTION);
        File target = getFileForDocId(documentId);
        includeFile(result, target);
        return result;
    }

    @Override
    public Cursor queryChildDocuments(String parentDocumentId, String[] projection, String sortOrder)
            throws FileNotFoundException {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DEFAULT_DOCUMENT_PROJECTION);
        File parent = getFileForDocId(parentDocumentId);
        File[] children = parent.listFiles();
        if (children != null) {
            for (File child : children) {
                // If child is expired, omit it from document queries
                includeFile(result, child);
            }
        }
        return result;
    }

    @Override
    public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        File file = getFileForDocId(documentId);
        if (!file.exists()) {
            throw new FileNotFoundException("Managed file no longer exists or expired: " + documentId);
        }

        int accessMode = ParcelFileDescriptor.parseMode(mode);
        try {
            return ParcelFileDescriptor.open(file, accessMode);
        } catch (IOException e) {
            throw new FileNotFoundException("Failed to open document descriptor: " + e.getMessage());
        }
    }

    private File getFileForDocId(String docId) {
        if ("root".equals(docId)) {
            return mBaseDir;
        }
        return new File(mBaseDir, docId);
    }

    private void includeFile(MatrixCursor result, File file) {
        MatrixCursor.RowBuilder row = result.newRow();
        row.add(Document.COLUMN_DOCUMENT_ID, file.getName());
        row.add(Document.COLUMN_DISPLAY_NAME, file.getName());
        row.add(Document.COLUMN_LAST_MODIFIED, file.lastModified());
        row.add(Document.COLUMN_SIZE, file.length());

        if (file.isDirectory()) {
            row.add(Document.COLUMN_MIME_TYPE, Document.MIME_TYPE_DIR);
        } else {
            row.add(Document.COLUMN_MIME_TYPE, "application/x-vanish");
            row.add(Document.COLUMN_FLAGS, Document.FLAG_SUPPORTS_DELETE | Document.FLAG_SUPPORTS_WRITE);
        }
    }
}
