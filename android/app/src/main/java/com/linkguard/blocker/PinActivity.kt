package com.linkguard.blocker

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.Gravity
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * 密码页。加域名、看记录都要过这一关。
 *
 * 为什么要密码：白名单的强度完全取决于"谁能往里加"。如果老人自己能加，
 * 否则仅凭社工话术（例如「点击允许即可查看」）即可绕过全部限制。
 *
 * 首次进入是设置密码（输两次），之后是验证。
 *
 * 显示方式：默认隐藏（显示为圆点），底部有「显示密码」开关可以临时看见数字。
 * 隐藏用的是 PasswordTransformationMethod，而不是靠 inputType 里的
 * NUMBER_VARIATION_PASSWORD —— 后者在部分机型上切换不可靠。
 */
class PinActivity : Activity() {

    companion object {
        const val EXTRA_MODE = "mode"
        const val MODE_SETUP = "setup"
        const val MODE_VERIFY = "verify"
    }

    private var mode: String = MODE_VERIFY
    private lateinit var input1: EditText
    private lateinit var input2: EditText
    private lateinit var hint: TextView
    private lateinit var submitButton: Button
    private lateinit var showToggle: CheckBox

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_VERIFY

        val root = Ui.root(this)
        val scroll = ScrollView(this)
        scroll.addView(root)
        setContentView(scroll)

        root.addView(Ui.topBar(this, if (mode == MODE_SETUP) "设置管理密码" else "输入管理密码") { finish() })

        val card = Ui.card(this)
        card.addView(Ui.text(this,
            if (mode == MODE_SETUP)
                "请设置一个仅家庭成员知晓的数字密码。\n用于修改白名单等管理操作。\n\n" +
                    "建议使用 6 位数字，避免生日等易猜组合。"
            else
                "请输入管理密码。",
            15f, Ui.TEXT
        ))
        root.addView(card)

        input1 = EditText(this).apply {
            hint = if (mode == MODE_SETUP) "新密码（4–8 位数字）" else "密码"
            // 只要数字键盘；隐藏/显示由 transformationMethod 控制
            inputType = InputType.TYPE_CLASS_NUMBER
            textSize = 22f
            gravity = Gravity.CENTER
            setSingleLine()
        }
        root.addView(input1, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this, 56)
        ))

        input2 = EditText(this).apply {
            hint = "再输一次"
            inputType = InputType.TYPE_CLASS_NUMBER
            textSize = 22f
            gravity = Gravity.CENTER
            setSingleLine()
            visibility = if (mode == MODE_SETUP) android.view.View.VISIBLE else android.view.View.GONE
        }
        root.addView(input2, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this, 56)
        ))

        // 视觉加密开关：默认不勾选 = 显示为圆点
        showToggle = CheckBox(this).apply {
            text = "显示密码"
            textSize = 15f
            isChecked = false
            setPadding(0, Ui.dp(this@PinActivity, 8), 0, 0)
            setOnCheckedChangeListener { _, checked -> applyMasking(checked) }
        }
        root.addView(showToggle)

        hint = Ui.text(this, "", 14f, Ui.RED).apply {
            setPadding(0, Ui.dp(this@PinActivity, 4), 0, 0)
        }
        root.addView(hint)

        submitButton = Ui.primaryButton(this, if (mode == MODE_SETUP) "设置管理密码" else "确认") {
            submit()
        }
        root.addView(submitButton)

        // 初始状态：隐藏
        applyMasking(false)
        input1.requestFocus()
    }

    /**
     * 切换两个输入框的显示方式，并保持光标位置。
     *
     * 必须先设 inputType 再设 transformationMethod：setInputType() 会把
     * transformationMethod 重置掉，顺序反了就不生效。
     */
    private fun applyMasking(visible: Boolean) {
        listOf(input1, input2).forEach { et ->
            val cursor = et.selectionEnd.coerceAtLeast(0)
            et.inputType = InputType.TYPE_CLASS_NUMBER
            et.transformationMethod =
                if (visible) null else PasswordTransformationMethod.getInstance()
            val len = et.text?.length ?: 0
            if (len > 0) et.setSelection(cursor.coerceIn(0, len))
        }
    }

    private fun submit() {
        val p1 = input1.text.toString().trim()
        if (p1.length !in 4..8 || p1.any { !it.isDigit() }) {
            hint.text = "请输入 4–8 位数字"
            return
        }
        if (mode == MODE_SETUP) {
            val p2 = input2.text.toString().trim()
            if (p1 != p2) {
                hint.text = "两次输入不一致"
                input2.setText("")
                return
            }
            Prefs.setPin(this, p1)
            Ui.toast(this, "密码设置成功")
            setResult(RESULT_OK)
            finish()
            return
        }
        if (Prefs.checkPin(this, p1)) {
            Prefs.clearPinFailures(this)
            setResult(RESULT_OK)
            finish()
            return
        }

        // 失败次数限制：4 位数字只有 1 万种，不限次的话几十秒就能穷举完
        val fails = Prefs.notePinFailure(this)
        input1.setText("")
        if (fails < 5) {
            hint.text = "密码错误，还可尝试 ${5 - fails} 次"
            return
        }
        val waitSec = minOf(60, (fails - 4) * 15)
        hint.text = "尝试次数过多，请 $waitSec 秒后重试"
        submitButton.isEnabled = false
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            submitButton.isEnabled = true
            hint.text = ""
        }, waitSec * 1000L)
    }
}
