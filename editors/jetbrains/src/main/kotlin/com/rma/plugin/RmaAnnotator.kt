package com.rma.plugin

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Document
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

class RmaAnnotator : ExternalAnnotator<PsiFile, List<Finding>>() {

    override fun collectInformation(file: PsiFile): PsiFile = file

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): PsiFile = file

    override fun doAnnotate(file: PsiFile): List<Finding> {
        val service = RmaService.getInstance(file.project)
        val path = file.virtualFile?.path ?: return emptyList()

        // Request analysis if not already cached
        if (!service.findings.containsKey(path) && service.isConnected()) {
            service.analyzeFile(path)
        }

        return service.findings[path] ?: emptyList()
    }

    override fun apply(file: PsiFile, findings: List<Finding>, holder: AnnotationHolder) {
        val document = file.viewProvider.document ?: return

        for (finding in findings) {
            val textRange = getTextRange(document, finding.line, finding.column)
            if (textRange != null) {
                val severity = when (finding.severity.lowercase()) {
                    "critical" -> HighlightSeverity.ERROR
                    "error" -> HighlightSeverity.ERROR
                    "warning" -> HighlightSeverity.WARNING
                    else -> HighlightSeverity.INFORMATION
                }

                holder.newAnnotation(severity, "[${finding.ruleId}] ${finding.message}")
                    .range(textRange)
                    .tooltip(buildTooltip(finding))
                    .create()
            }
        }
    }

    private fun getTextRange(document: Document, line: Int, column: Int): TextRange? {
        if (line < 1 || line > document.lineCount) return null

        val lineStartOffset = document.getLineStartOffset(line - 1)
        val lineEndOffset = document.getLineEndOffset(line - 1)
        val startOffset = (lineStartOffset + column - 1).coerceIn(lineStartOffset, lineEndOffset)

        // Highlight to end of token or line
        val text = document.getText(TextRange(startOffset, lineEndOffset))
        val endOffset = startOffset + (text.takeWhile { !it.isWhitespace() && it != '(' && it != ')' }.length)
            .coerceAtLeast(1)

        return TextRange(startOffset, endOffset.coerceAtMost(lineEndOffset))
    }

    private fun buildTooltip(finding: Finding): String {
        return """
            <html>
            <b>RMA: ${finding.ruleId}</b><br/>
            ${finding.message}<br/>
            <i>Severity: ${finding.severity}</i>
            </html>
        """.trimIndent()
    }
}
