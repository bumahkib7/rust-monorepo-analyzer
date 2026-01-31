package com.rma.plugin

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.Disposable
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import org.java_websocket.client.WebSocketClient
import org.java_websocket.handshake.ServerHandshake
import java.net.URI
import java.util.concurrent.ConcurrentHashMap

@Service(Service.Level.PROJECT)
class RmaService(private val project: Project) : Disposable {
    private val log = Logger.getInstance(RmaService::class.java)
    private val gson = Gson()

    private var wsClient: RmaWebSocketClient? = null
    private var daemonHost = "localhost"
    private var daemonPort = 8080

    // Cache of findings by file path
    val findings = ConcurrentHashMap<String, List<Finding>>()

    // Listeners for real-time updates
    private val listeners = mutableListOf<RmaListener>()

    fun connect() {
        if (wsClient?.isOpen == true) {
            log.info("Already connected to RMA daemon")
            return
        }

        val uri = URI("ws://$daemonHost:$daemonPort/ws/watch")
        wsClient = RmaWebSocketClient(uri, this)
        wsClient?.connect()
    }

    fun disconnect() {
        wsClient?.close()
        wsClient = null
    }

    fun isConnected(): Boolean = wsClient?.isOpen == true

    fun startWatching(path: String) {
        val cmd = JsonObject().apply {
            addProperty("command", "Watch")
            add("data", JsonObject().apply {
                addProperty("path", path)
            })
        }
        wsClient?.send(gson.toJson(cmd))
    }

    fun stopWatching() {
        val cmd = JsonObject().apply {
            addProperty("command", "StopWatch")
        }
        wsClient?.send(gson.toJson(cmd))
    }

    fun analyzeFile(path: String) {
        val cmd = JsonObject().apply {
            addProperty("command", "Analyze")
            add("data", JsonObject().apply {
                addProperty("path", path)
            })
        }
        wsClient?.send(gson.toJson(cmd))
    }

    fun addListener(listener: RmaListener) {
        listeners.add(listener)
    }

    fun removeListener(listener: RmaListener) {
        listeners.remove(listener)
    }

    internal fun onMessage(message: String) {
        try {
            val json = gson.fromJson(message, JsonObject::class.java)
            val type = json.get("type")?.asString ?: return
            val data = json.get("data")?.asJsonObject

            when (type) {
                "Connected" -> {
                    val clientId = data?.get("client_id")?.asString
                    log.info("Connected to RMA daemon: $clientId")
                    notify("Connected to RMA daemon", NotificationType.INFORMATION)

                    // Start watching project directory
                    project.basePath?.let { startWatching(it) }
                }

                "FileChanged" -> {
                    val path = data?.get("path")?.asString ?: return
                    val kind = data.get("kind")?.asString ?: "unknown"
                    log.debug("File changed: $path ($kind)")
                }

                "AnalysisComplete" -> {
                    val path = data?.get("path")?.asString ?: return
                    val findingsJson = data.getAsJsonArray("findings")
                    val durationMs = data.get("duration_ms")?.asLong ?: 0

                    val fileFindings = findingsJson.map { f ->
                        val obj = f.asJsonObject
                        Finding(
                            ruleId = obj.get("rule_id")?.asString ?: "",
                            message = obj.get("message")?.asString ?: "",
                            severity = obj.get("severity")?.asString ?: "info",
                            line = obj.get("line")?.asInt ?: 0,
                            column = obj.get("column")?.asInt ?: 0
                        )
                    }

                    findings[path] = fileFindings
                    log.info("Analysis complete: $path (${fileFindings.size} findings in ${durationMs}ms)")

                    // Notify listeners
                    listeners.forEach { it.onAnalysisComplete(path, fileFindings) }
                }

                "Error" -> {
                    val errorMsg = data?.get("message")?.asString ?: "Unknown error"
                    log.error("RMA error: $errorMsg")
                    notify("RMA Error: $errorMsg", NotificationType.ERROR)
                }

                "WatchingStarted" -> {
                    val path = data?.get("path")?.asString
                    log.info("Now watching: $path")
                }
            }
        } catch (e: Exception) {
            log.error("Failed to parse RMA message: $message", e)
        }
    }

    internal fun onConnected() {
        listeners.forEach { it.onConnected() }
    }

    internal fun onDisconnected() {
        listeners.forEach { it.onDisconnected() }
        notify("Disconnected from RMA daemon", NotificationType.WARNING)
    }

    internal fun onError(ex: Exception) {
        log.error("WebSocket error", ex)
        notify("RMA connection error: ${ex.message}", NotificationType.ERROR)
    }

    private fun notify(content: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("RMA Notifications")
            .createNotification(content, type)
            .notify(project)
    }

    override fun dispose() {
        disconnect()
    }

    companion object {
        fun getInstance(project: Project): RmaService {
            return project.getService(RmaService::class.java)
        }
    }
}

data class Finding(
    val ruleId: String,
    val message: String,
    val severity: String,
    val line: Int,
    val column: Int
)

interface RmaListener {
    fun onConnected() {}
    fun onDisconnected() {}
    fun onAnalysisComplete(path: String, findings: List<Finding>) {}
}

private class RmaWebSocketClient(
    uri: URI,
    private val service: RmaService
) : WebSocketClient(uri) {

    override fun onOpen(handshake: ServerHandshake?) {
        service.onConnected()
    }

    override fun onMessage(message: String?) {
        message?.let { service.onMessage(it) }
    }

    override fun onClose(code: Int, reason: String?, remote: Boolean) {
        service.onDisconnected()
    }

    override fun onError(ex: Exception?) {
        ex?.let { service.onError(it) }
    }
}
