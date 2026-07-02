/*
 * Copyright 2026 Arx Secretorum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.arxnotes.core.crypto

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Корень доверия приложения: один случайный 256-битный **мастер-секрет**, обёрнутый
 * AES-GCM-ключом из Android Keystore (аппаратно-защищённым, где доступно). На диск
 * пишется только зашифрованный блоб (формат [AeadBlob]); ключ-обёртка не покидает Keystore.
 *
 * Рабочие ключи получаются из мастера через **HKDF** с доменной меткой — это даёт
 * независимые подключи под каждое назначение (БД, аудио). Один и тот же секрет не
 * переиспользуется напрямую в двух криптосистемах.
 *
 * Соответствует разд. 9.2 ТЗ. EncryptedSharedPreferences НЕ используется (разд. 9.5).
 */
/** Ключ БД недоступен, потому что устройство заблокировано (setUnlockedDeviceRequired). НЕ порча данных. */
class DeviceLockedException : Exception("Device is locked; DB key unavailable")

/** Keystore аннулировал ключ-обёртку (смена учётных данных экрана/перенос устройства) → мастер-секрет и данные невосстановимы. НЕ порча блоба. */
class KeyInvalidatedException : Exception("Keystore wrap key permanently invalidated; data unrecoverable")

/**
 * Выполняет [block]; единственное преобразование — аннулированный Keystore-ключ
 * (`KeyPermanentlyInvalidatedException`) превращаем в доменный [KeyInvalidatedException].
 * Вынесено отдельно, чтобы маппинг можно было покрыть инструментальным тестом (саму
 * аннуляцию ОС в автотесте вызвать нельзя — нужна ручная смена защиты экрана).
 */
internal fun <T> mapKeystoreInvalidation(block: () -> T): T =
    try {
        block()
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeyInvalidatedException()
    }

class MasterKeyManager(private val context: Context) {

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val blobFile: File get() = File(context.filesDir, BLOB_FILENAME)

    /** Ключ-парольная фраза для SQLCipher (подключ домена «db»). */
    fun databaseKey(): ByteArray = deriveSubkey(INFO_DB)

    /** Ключ AES-256 для шифрования голосовых заметок (подключ домена «audio»). */
    fun audioKey(): ByteArray = deriveSubkey(INFO_AUDIO)

    private fun deriveSubkey(info: ByteArray): ByteArray {
        val master = getOrCreateMaster()
        return try {
            Hkdf.derive(ikm = master, salt = null, info = info, length = KEY_BYTES)
        } finally {
            master.fill(0)   // не держим мастер-секрет в памяти дольше необходимого
        }
    }

    /** Возвращает мастер-секрет, создавая и сохраняя его при первом вызове. */
    private fun getOrCreateMaster(): ByteArray {
        ensureKeystoreKey()
        return if (blobFile.exists()) decryptBlob() else createAndStoreMaster()
    }

    private fun ensureKeystoreKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) return
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // Ключ-обёртку нельзя использовать, пока устройство заблокировано → защита от
            // извлечения БД на заблокированном (но включённом) телефоне. Напоминания берут
            // текст из интента (не из БД), а виджет под замком показывает «замок» (ArxNotesWidget),
            // поэтому функциональность не страдает. На устройстве без блокировки — no-op.
            builder.setUnlockedDeviceRequired(true)
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply {
            init(builder.build())
            generateKey()
        }
    }

    /** Устройство заблокировано (с защищённым экраном) → ключ-обёртка временно недоступен. */
    private fun isDeviceLocked(): Boolean =
        context.getSystemService(KeyguardManager::class.java)?.isDeviceLocked == true

    private fun secretKey(): SecretKey =
        (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey

    private fun createAndStoreMaster(): ByteArray {
        val master = ByteArray(KEY_BYTES).also { SecureRandom().nextBytes(it) }
        val blob = AeadBlob.seal(secretKey(), master, BLOB_VERSION)
        // Пишем атомарно (во временный файл + переименование), чтобы прерывание не оставило
        // битый блоб; fd.sync() гарантирует данные на диске ДО переименования (защита при сбое питания).
        val tmp = File(context.filesDir, "$BLOB_FILENAME.tmp")
        tmp.outputStream().use { out ->
            out.write(blob)
            out.flush()
            out.fd.sync()
        }
        check(tmp.renameTo(blobFile)) { "Failed to persist key blob" }
        return master
    }

    private fun decryptBlob(): ByteArray {
        // Keystore аннулировал ключ-обёртку (смена учётных данных экрана блокировки,
        // перенос на новое устройство) → мастер-секрет невосстановим, как и БД/аудио.
        // Это НЕ порча блоба — отдаём отдельный сигнал (KeyInvalidatedException), чтобы не спутать.
        val opened = mapKeystoreInvalidation {
            AeadBlob.open(secretKey(), blobFile.readBytes(), BLOB_VERSION)
        }
        if (opened != null) return opened
        // null = два разных случая, и их НЕЛЬЗЯ путать:
        //  • устройство заблокировано — ключ-обёртка недоступен (setUnlockedDeviceRequired),
        //    это НЕ порча: бросаем DeviceLockedException, вызывающий покажет «замок»/повторит;
        //  • реальная порча блоба — молча перегенерировать мастер нельзя (осиротеет БД) → ошибка.
        if (isDeviceLocked()) throw DeviceLockedException()
        error("Corrupt key blob")
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"

        // FROZEN — НЕ ПЕРЕИМЕНОВЫВАТЬ. Это alias записи в Android Keystore, а НЕ имя приложения.
        // «safenote» здесь — исторический непрозрачный идентификатор, не бренд; его текст НЕ обязан
        // совпадать с «Arx Notes». Смена значения ⇒ приложение не найдёт уже созданный ключ-обёртку
        // ⇒ мастер-секрет и все данные пользователя станут недоступны. Не «чистить» под ребрендинг.
        const val KEY_ALIAS = "safenote_master_key"

        const val BLOB_FILENAME = "master_key.bin"
        const val KEY_BYTES = 32         // 256 бит
        const val BLOB_VERSION: Byte = 1 // версия формата обёртки мастер-секрета

        // FROZEN — НЕ ПЕРЕИМЕНОВЫВАТЬ. Доменные метки HKDF (domain separation), а НЕ бренд.
        // «safenote» здесь — фиксированная строка-константа; её байты входят в деривацию подключей
        // БД/аудио. Смена ⇒ выведутся ДРУГИЕ ключи ⇒ уже зашифрованные БД и аудио не расшифруются.
        // Менять допустимо ТОЛЬКО через миграцию с бампом версии (напр. «/v2»: читать старым ключом
        // → перешифровать новым). Не трогать ради совпадения с брендом.
        val INFO_DB = "app.safenote/db/v1".toByteArray(Charsets.US_ASCII)
        val INFO_AUDIO = "app.safenote/audio/v1".toByteArray(Charsets.US_ASCII)
    }
}
