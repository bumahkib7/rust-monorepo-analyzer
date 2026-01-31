package com.rma.plugin

import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

class RmaConfigurable(private val project: Project) : Configurable {
    private var hostField: JBTextField? = null
    private var portField: JBTextField? = null
    private var autoConnectCheckbox: JBCheckBox? = null

    override fun getDisplayName(): String = "RMA Settings"

    override fun createComponent(): JComponent {
        hostField = JBTextField("localhost")
        portField = JBTextField("8080")
        autoConnectCheckbox = JBCheckBox("Auto-connect on project open", true)

        return FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Daemon Host:"), hostField!!, 1, false)
            .addLabeledComponent(JBLabel("Daemon Port:"), portField!!, 1, false)
            .addComponent(autoConnectCheckbox!!, 1)
            .addComponentFillVertically(JPanel(), 0)
            .panel
    }

    override fun isModified(): Boolean {
        // Check if settings have been modified
        return true
    }

    override fun apply() {
        // Save settings
        // In a real implementation, you'd persist these to PropertiesComponent
    }

    override fun reset() {
        hostField?.text = "localhost"
        portField?.text = "8080"
        autoConnectCheckbox?.isSelected = true
    }
}
