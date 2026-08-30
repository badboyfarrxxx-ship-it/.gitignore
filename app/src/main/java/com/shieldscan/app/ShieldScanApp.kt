package com.shieldscan.app

import android.app.Application
import com.shieldscan.app.data.db.AppDatabase
import com.shieldscan.app.data.db.ScanHistoryRepository
import com.shieldscan.app.data.signature.SignatureRepository
import com.shieldscan.app.scanner.FileScanner
import com.shieldscan.app.scanner.PackageScanner

/** Simple hand-rolled service locator — no DI framework needed for an app this size. */
class ShieldScanApp : Application() {

    val signatureRepository: SignatureRepository by lazy { SignatureRepository(this) }

    val packageScanner: PackageScanner by lazy { PackageScanner(this, signatureRepository) }

    val fileScanner: FileScanner by lazy { FileScanner(this, signatureRepository) }

    val scanHistoryRepository: ScanHistoryRepository by lazy {
        ScanHistoryRepository(AppDatabase.getInstance(this).scanHistoryDao())
    }
}
