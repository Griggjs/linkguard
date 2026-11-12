package com.linkguard.blocker

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * 界面用代码拼，不用 XML。
 *
 * 原因：这不是给开发者看的工程，是要能一次编译通过的交付物。
 * 代码写界面能少掉 布局文件、资源 ID、findViewById 三处出错点，
 * 而且我这边没有真机可以点一遍，出错点越少越好。
 */
object Ui {

    const val BG = 0xFFF5F6F8.toInt()
    const val CARD = 0xFFFFFFFF.toInt()
    const val TITLE = 0xFF1B3A63.toInt()
    const val TEXT = 0xFF1A1A1A.toInt()
    const val MUTED = 0xFF5A6472.toInt()
    const val GREEN = 0xFF2E7D32.toInt()
    const val ORANGE = 0xFFE65100.toInt()
    const val RED = 0xFFC62828.toInt()
    const val BLUE = 0xFF1B6FD6.toInt()
    const val DIVIDER = 0xFFE6E8EC.toInt()

    fun dp(ctx: Context, v: Int): Int =
        (v * ctx.resources.displayMetrics.density).toInt()

    fun root(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(BG)
        setPadding(dp(ctx, 16), dp(ctx, 24), dp(ctx, 16), dp(ctx, 24))
    }

    fun card(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(CARD)
        setPadding(dp(ctx, 18), dp(ctx, 18), dp(ctx, 18), dp(ctx, 18))
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        )
        lp.bottomMargin = dp(ctx, 14)
        layoutParams = lp
        background = GradientDrawable().apply {
            cornerRadius = dp(ctx, 14).toFloat()
            setColor(CARD)
        }
    }

    /** 给卡片换底色（用于"保护中/未保护"这种一眼要看清的状态）。 */
    fun tintCard(card: LinearLayout, color: Int) {
        val ctx = card.context
        card.background = GradientDrawable().apply {
            cornerRadius = dp(ctx, 14).toFloat()
            setColor(color)
        }
    }

    fun text(ctx: Context, s: CharSequence, sizeSp: Float, color: Int = TEXT): TextView =
        TextView(ctx).apply {
            text = s
            textSize = sizeSp
            setTextColor(color)
            setLineSpacing(dp(ctx, 4).toFloat(), 1f)
        }

    fun heading(ctx: Context, s: CharSequence): TextView =
        text(ctx, s, 15f, MUTED)

    fun bigStatus(ctx: Context, s: CharSequence, color: Int): TextView =
        text(ctx, s, 24f, color).apply {
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }

    fun primaryButton(ctx: Context, s: CharSequence, onClick: View.OnClickListener): Button =
        Button(ctx).apply {
            text = s
            textSize = 18f
            isAllCaps = false
            setOnClickListener(onClick)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(ctx, 56)
            )
            lp.bottomMargin = dp(ctx, 12)
            layoutParams = lp
        }

    fun secondaryButton(ctx: Context, s: CharSequence, onClick: View.OnClickListener): Button =
        Button(ctx).apply {
            text = s
            textSize = 16f
            isAllCaps = false
            setOnClickListener(onClick)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(ctx, 48)
            )
            lp.bottomMargin = dp(ctx, 10)
            layoutParams = lp
        }

    fun divider(ctx: Context): View = View(ctx).apply {
        setBackgroundColor(DIVIDER)
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            dp(ctx, 1)
        )
        lp.topMargin = dp(ctx, 8)
        lp.bottomMargin = dp(ctx, 8)
        layoutParams = lp
    }

    fun row(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        )
        lp.topMargin = dp(ctx, 6)
        layoutParams = lp
    }

    fun spacer(ctx: Context, weight: Float = 1f): View = View(ctx).apply {
        layoutParams = LinearLayout.LayoutParams(0, 0, weight)
    }

    /** 顶栏：返回按钮 + 标题。 */
    fun topBar(ctx: Context, title: String, onBack: (() -> Unit)?): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(ctx, 16))
            if (onBack != null) {
                addView(Button(ctx).apply {
                    text = "返回"
                    textSize = 14f
                    isAllCaps = false
                    minimumWidth = 0
                    setPadding(dp(ctx, 10), 0, dp(ctx, 10), 0)
                    setOnClickListener { onBack() }
                })
            }
            addView(text(ctx, title, 20f, TITLE).apply {
                setTypeface(typeface, android.graphics.Typeface.BOLD)
                setPadding(dp(ctx, 10), 0, 0, 0)
            })
        }

    fun toast(ctx: Context, msg: String) {
        android.widget.Toast.makeText(ctx, msg, android.widget.Toast.LENGTH_SHORT).show()
    }

    fun parseColor(hex: String): Int = Color.parseColor(hex)

    fun spToPx(ctx: Context, sp: Float): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, sp, ctx.resources.displayMetrics).toInt()
}
