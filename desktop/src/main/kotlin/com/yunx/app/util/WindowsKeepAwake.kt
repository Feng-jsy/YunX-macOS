package com.yunx.app.util

import com.sun.jna.Native
import com.sun.jna.win32.StdCallLibrary
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * 下载期间阻止系统睡眠（Windows）：
 * kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)。
 * 该状态是线程本地属性，所有调用固定投递到同一线程执行，引用计数归零时解除。
 */
object WindowsKeepAwake {
    private interface Kernel32 : StdCallLibrary {
        fun SetThreadExecutionState(esFlags: Int): Int

        companion object {
            // ★ 用 lazy：避免非 Windows 平台在类加载时就去 Native.load("kernel32") 直接崩掉
            val INSTANCE: Kernel32 by lazy { Native.load("kernel32", Kernel32::class.java) }
        }
    }

    private const val ES_CONTINUOUS = 0x80000000.toInt()
    private const val ES_SYSTEM_REQUIRED = 0x00000001

    private val osName = System.getProperty("os.name", "").lowercase()
    private val isWindows = osName.contains("win")
    private val isMac = osName.contains("mac")

    /** 所有保活调用固定在此线程（Windows 状态线程本地、跨线程会失调） */
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "yunx-keep-awake") }
    private val refs = AtomicInteger(0)

    /** macOS：caffeinate 子进程（防止系统空闲睡眠），释放时 destroy */
    @Volatile
    private var caffeinate: Process? = null

    fun acquire() {
        if (refs.getAndIncrement() == 0) {
            executor.execute {
                when {
                    isMac -> runCatching {
                        caffeinate = ProcessBuilder("caffeinate", "-i").start()
                    }.onFailure { Log.w("YunX-KeepAwake", "caffeinate 启动失败：${it.message}") }
                    isWindows -> runCatching {
                        Kernel32.INSTANCE.SetThreadExecutionState(ES_CONTINUOUS or ES_SYSTEM_REQUIRED)
                    }
                }
            }
        }
    }

    fun release() {
        if (refs.decrementAndGet() <= 0) {
            refs.set(0)
            executor.execute {
                when {
                    isMac -> runCatching { caffeinate?.destroy() }.also { caffeinate = null }
                    isWindows -> runCatching { Kernel32.INSTANCE.SetThreadExecutionState(ES_CONTINUOUS) }
                }
            }
        }
    }
}
