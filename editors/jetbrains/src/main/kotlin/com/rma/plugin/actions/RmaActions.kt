package com.rma.plugin.actions

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.rma.plugin.RmaService
import java.io.File

class AnalyzeFileAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val editor = e.getData(CommonDataKeys.EDITOR) ?: return
        val document = editor.document
        val file = FileDocumentManager.getInstance().getFile(document) ?: return

        val service = RmaService.getInstance(project)
        if (service.isConnected()) {
            service.analyzeFile(file.path)
        } else {
            service.connect()
        }
    }

    override fun update(e: AnActionEvent) {
        val project = e.project
        val editor = e.getData(CommonDataKeys.EDITOR)
        e.presentation.isEnabled = project != null && editor != null
    }
}

class AnalyzeProjectAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: return

        val service = RmaService.getInstance(project)
        if (!service.isConnected()) {
            service.connect()
        }
        service.startWatching(basePath)
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }
}

class StartDaemonAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        // Try to start the daemon
        try {
            val process = ProcessBuilder("rma", "daemon", "--port", "8080")
                .directory(File(project.basePath ?: "."))
                .start()

            // Wait a bit for daemon to start
            Thread.sleep(1000)

            // Connect to it
            val service = RmaService.getInstance(project)
            service.connect()
        } catch (ex: Exception) {
            // Daemon might not be installed
        }
    }

    override fun update(e: AnActionEvent) {
        val project = e.project ?: return
        val service = RmaService.getInstance(project)
        e.presentation.isEnabled = !service.isConnected()
    }
}

class StopDaemonAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val service = RmaService.getInstance(project)
        service.disconnect()

        // Try to stop the daemon process
        try {
            ProcessBuilder("pkill", "-f", "rma daemon").start()
        } catch (ex: Exception) {
            // Ignore
        }
    }

    override fun update(e: AnActionEvent) {
        val project = e.project ?: return
        val service = RmaService.getInstance(project)
        e.presentation.isEnabled = service.isConnected()
    }
}
