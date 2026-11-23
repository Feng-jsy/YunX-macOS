/*
 * YunX (云析) - A network drive share-link parser and high-speed downloader for Android.
 * Copyright (C) 2026 CYQawa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.yunx.app.util

import com.sun.jna.platform.win32.Crypt32Util
import com.yunx.app.AppContext
import java.io.File
import java.sql.DriverManager
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * 一键从本机浏览器导入网盘登录 Cookie（方案 A）。
 *
 * - Chromium 系（Chrome / Edge / 360 / QQ / 搜狗 / Opera / Brave 等）：
 *   - Windows：`Network\Cookies`（SQLite）中 encrypted_value 为 "v10" 前缀 + Windows DPAPI 加密载荷，
 *     用 CryptUnprotectData 解密（同一 Windows 用户下可解）。"v20" 前缀为「应用绑定加密」（Chrome 127+），
 *     无法解密 → 跳过该 Cookie。
 *   - macOS：`<profile>/Cookies`（SQLite）中 encrypted_value 为 "v10" 前缀 + AES-128-CBC 加密载荷，
 *     密钥由 Keychain 里的 "<Browser> Safe Storage" 口令经 PBKDF2 派生（salt="saltysalt"、1003 次迭代），
 *     IV 为 16 个空格。首次访问会触发系统 Keychain 授权弹窗。
 * - Firefox：cookies.sqlite 中 value 为明文，直接读取（Windows / macOS 同）。
 */
object BrowserCookieImporter {

    private const val TAG = "YunX-Cookie"

    private val isMac = System.getProperty("os.name", "").lowercase().contains("mac")

    enum class Kind { CHROMIUM, FIREFOX }

    data class BrowserInfo(
        val id: String,
        val displayName: String,
        val kind: Kind,
        val profileDirs: List<File>,
        /** macOS Chromium 系：Keychain 里的 Safe Storage 服务名（Windows 为 null） */
        val keychainService: String? = null
    )

    data class FoundCookies(
        val browserName: String,
        val cookie: String,
        val count: Int
    )

    /** 平台 → 需要匹配的 Cookie 域名后缀 */
    fun domainSuffixes(platform: String): List<String> = when (platform) {
        "QUARK" -> listOf(".quark.cn")
        "UC" -> listOf(".uc.cn")
        "BAIDU" -> listOf(".baidu.com")
        "C139" -> listOf("mail.10086.cn", "yun.139.com", ".10086.cn")
        "PAN115" -> listOf(".115.com", ".115cdn.com")
        else -> emptyList()
    }

    /** 发现本机已安装浏览器的 Cookie 库目录（存在 cookies 文件才算） */
    fun discoverBrowsers(): List<BrowserInfo> =
        if (isMac) discoverMacBrowsers() else discoverWindowsBrowsers()

    private fun discoverWindowsBrowsers(): List<BrowserInfo> {
        val local = System.getenv("LOCALAPPDATA")?.let { File(it) } ?: return emptyList()
        val roaming = System.getenv("APPDATA")?.let { File(it) } ?: return emptyList()
        val out = mutableListOf<BrowserInfo>()

        val chromiumCandidates = listOf(
            "Chrome" to listOf(File(local, "Google\\Chrome\\User Data")),
            "Edge" to listOf(File(local, "Microsoft\\Edge\\User Data")),
            "360极速浏览器" to listOf(File(local, "360Chrome\\Chrome\\User Data")),
            "360安全浏览器" to listOf(
                File(roaming, "360se6\\User Data"),
                File(roaming, "360se\\User Data"),
                File(local, "360se6\\User Data")
            ),
            "QQ浏览器" to listOf(File(local, "Tencent\\QQBrowser\\User Data")),
            "搜狗浏览器" to listOf(
                File(roaming, "SogouExplorer\\User Data"),
                File(local, "SogouExplorer\\User Data")
            ),
            "Opera" to listOf(File(roaming, "Opera Software\\Opera Stable")),
            "Brave" to listOf(File(local, "BraveSoftware\\Brave-Browser\\User Data")),
            "Vivaldi" to listOf(File(local, "Vivaldi\\User Data"))
        )
        for ((name, roots) in chromiumCandidates) {
            val existing = roots.filter { root ->
                root.isDirectory && File(root, "Network\\Cookies").exists()
            }
            if (existing.isNotEmpty()) {
                out += BrowserInfo("chromium-$name", name, Kind.CHROMIUM, existing)
            }
        }

        val ffRoot = File(roaming, "Mozilla\\Firefox\\Profiles")
        if (ffRoot.isDirectory) {
            val profiles = ffRoot.listFiles { f -> f.isDirectory && File(f, "cookies.sqlite").exists() }
                ?.toList() ?: emptyList()
            if (profiles.isNotEmpty()) {
                out += BrowserInfo("firefox", "Firefox", Kind.FIREFOX, profiles)
            }
        }
        return out
    }

    /** macOS：浏览器数据在 `~/Library/Application Support` 下，Cookie 库为 `<profile>/Cookies` */
    private fun discoverMacBrowsers(): List<BrowserInfo> {
        val home = System.getProperty("user.home") ?: return emptyList()
        val support = File(home, "Library/Application Support")
        val out = mutableListOf<BrowserInfo>()

        // (显示名, 根目录, Keychain Safe Storage 服务名)
        val chromiumCandidates = listOf(
            Triple("Chrome", File(support, "Google/Chrome"), "Chrome Safe Storage"),
            Triple("Edge", File(support, "Microsoft Edge"), "Microsoft Edge Safe Storage"),
            Triple("Brave", File(support, "BraveSoftware/Brave-Browser"), "Brave Safe Storage"),
            Triple("Chromium", File(support, "Chromium"), "Chromium Safe Storage")
        )
        for ((name, root, service) in chromiumCandidates) {
            if (!root.isDirectory) continue
            val profiles = buildList {
                add(File(root, "Default"))
                root.listFiles { f -> f.isDirectory && f.name.startsWith("Profile") }
                    ?.let { addAll(it) }
            }
            val existing = profiles.filter { File(it, "Cookies").exists() }
            if (existing.isNotEmpty()) {
                out += BrowserInfo("chromium-$name", name, Kind.CHROMIUM, existing, service)
            }
        }

        val ffRoot = File(support, "Firefox/Profiles")
        if (ffRoot.isDirectory) {
            val profiles = ffRoot.listFiles { f -> f.isDirectory && File(f, "cookies.sqlite").exists() }
                ?.toList() ?: emptyList()
            if (profiles.isNotEmpty()) {
                out += BrowserInfo("firefox", "Firefox", Kind.FIREFOX, profiles)
            }
        }
        return out
    }

    /** 从指定浏览器导入指定平台的 Cookie；未找到返回 null */
    fun importFrom(browser: BrowserInfo, domains: List<String>): FoundCookies? =
        when (browser.kind) {
            Kind.CHROMIUM -> importChromium(browser, domains)
            Kind.FIREFOX -> importFirefox(browser, domains)
        }

    // ---------- Chromium ----------

    private fun importChromium(browser: BrowserInfo, domains: List<String>): FoundCookies? {
        for (root in browser.profileDirs) {
            val cookiesFile = File(root, if (isMac) "Cookies" else "Network\\Cookies")
            if (!cookiesFile.exists()) continue
            val copy = File(AppContext.cacheDir, "browser-cookies-${System.nanoTime()}.db")
            try {
                cookiesFile.copyTo(copy, overwrite = true)
                val cookie = extractChromium(copy, domains, browser.keychainService) ?: continue
                return FoundCookies(browser.displayName, cookie, cookie.split(';').size)
            } catch (e: Exception) {
                Log.w(TAG, "读取 ${browser.displayName} Cookie 失败: ${e.message}")
            } finally {
                runCatching { copy.delete() }
            }
        }
        return null
    }

    private fun extractChromium(dbFile: File, domains: List<String>, keychainService: String?): String? {
        Class.forName("org.sqlite.JDBC")
        DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}").use { conn ->
            val likeClause = domains.joinToString(" OR ") { "host_key LIKE ?" }
            conn.prepareStatement(
                "SELECT host_key, name, encrypted_value FROM cookies WHERE $likeClause"
            ).use { st ->
                domains.forEachIndexed { i, d -> st.setString(i + 1, "%$d%") }
                st.executeQuery().use { rs ->
                    val pairs = mutableListOf<String>()
                    while (rs.next()) {
                        val name = rs.getString(2)
                        val value = decryptChromiumValue(rs.getBytes(3), keychainService) ?: continue
                        if (name.isNotBlank()) pairs += "$name=$value"
                    }
                    if (pairs.isEmpty()) return null
                    return pairs.joinToString("; ")
                }
            }
        }
    }

    /**
     * Chromium encrypted_value：
     * - "v10" 前缀 + 加密载荷 → Windows 用 DPAPI（CryptUnprotectData），macOS 用 Keychain 派生密钥的 AES-128-CBC；
     * - "v20" 前缀（应用绑定加密，Chrome 127+）→ 返回 null（无法解密，跳过后整体提示）；
     * - 无前缀（个别旧版）→ 直接按 DPAPI 尝试。
     */
    private fun decryptChromiumValue(bytes: ByteArray, keychainService: String?): String? {
        if (bytes.size < 3) return null
        var offset = 0
        if (bytes[0] == 'v'.code.toByte() &&
            bytes[1] in '0'.code.toByte()..'9'.code.toByte() &&
            bytes[2] in '0'.code.toByte()..'9'.code.toByte()
        ) {
            val version = (bytes[1] - '0'.code.toByte()) * 10 + (bytes[2] - '0'.code.toByte())
            if (version >= 20) return null // 应用绑定加密，无法解密
            offset = 3
        }
        val payload = if (offset > 0) bytes.copyOfRange(offset, bytes.size) else bytes
        return if (isMac) {
            decryptMacAes(payload, keychainService)
        } else {
            runCatching {
                val plain = Crypt32Util.cryptUnprotectData(payload)
                String(plain, Charsets.UTF_8)
            }.getOrNull()
        }
    }

    /**
     * macOS Chromium Cookie 解密：AES-128-CBC + PBKDF2-HMAC-SHA1 派生密钥。
     * - 密钥口令：Keychain 里的 `keychainService`（如 "Chrome Safe Storage"）；
     * - 派生：PBKDF2-HMAC-SHA1，salt="saltysalt"，1003 次迭代，128 bit；
     * - IV：16 个空格（0x20），PKCS5 填充。
     */
    private fun decryptMacAes(payload: ByteArray, keychainService: String?): String? {
        val service = keychainService ?: return null
        return runCatching {
            val password = readKeychainPassword(service) ?: return@runCatching null
            val salt = "saltysalt".toByteArray(Charsets.US_ASCII)
            val keySpec = PBEKeySpec(password.toCharArray(), salt, 1003, 128)
            val key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
                .generateSecret(keySpec).encoded
            val iv = ByteArray(16) { 0x20 }
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            String(cipher.doFinal(payload), Charsets.UTF_8)
        }.onFailure {
            Log.w(TAG, "macOS Cookie 解密失败（$keychainService）：${it.message}")
        }.getOrNull()
    }

    /** 从 macOS Keychain 读取 Safe Storage 口令（首次访问会弹系统授权框） */
    private fun readKeychainPassword(service: String): String? = runCatching {
        val process = ProcessBuilder("security", "find-generic-password", "-w", "-s", service).start()
        val text = process.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText().trim() }
        process.waitFor()
        text.takeIf { it.isNotBlank() }
    }.onFailure {
        Log.w(TAG, "读取 Keychain（$service）失败：${it.message}")
    }.getOrNull()

    // ---------- Firefox ----------

    private fun importFirefox(browser: BrowserInfo, domains: List<String>): FoundCookies? {
        for (profile in browser.profileDirs) {
            val dbFile = File(profile, "cookies.sqlite")
            if (!dbFile.exists()) continue
            val copy = File(AppContext.cacheDir, "ff-cookies-${System.nanoTime()}.db")
            try {
                dbFile.copyTo(copy, overwrite = true)
                val cookie = extractFirefox(copy, domains) ?: continue
                return FoundCookies(browser.displayName, cookie, cookie.split(';').size)
            } catch (e: Exception) {
                Log.w(TAG, "读取 Firefox Cookie 失败: ${e.message}")
            } finally {
                runCatching { copy.delete() }
            }
        }
        return null
    }

    private fun extractFirefox(dbFile: File, domains: List<String>): String? {
        Class.forName("org.sqlite.JDBC")
        DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}").use { conn ->
            val likeClause = domains.joinToString(" OR ") { "host LIKE ?" }
            conn.prepareStatement(
                "SELECT host, name, value FROM moz_cookies WHERE $likeClause"
            ).use { st ->
                domains.forEachIndexed { i, d -> st.setString(i + 1, "%$d%") }
                st.executeQuery().use { rs ->
                    val pairs = mutableListOf<String>()
                    while (rs.next()) {
                        val name = rs.getString(2)
                        val value = rs.getString(3)
                        if (name.isNotBlank()) pairs += "$name=$value"
                    }
                    if (pairs.isEmpty()) return null
                    return pairs.joinToString("; ")
                }
            }
        }
    }
}
