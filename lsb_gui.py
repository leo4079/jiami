#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LSB 隐写检测工具 - GUI 界面
基于 tkinter（Python 内置，无需安装依赖）

使用方法:
    python lsb_gui.py
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# 导入检测模块
from lsb_detect import (
    load_image,
    chi_square_analysis,
    rs_analysis,
    spa_analysis,
    visual_attack,
    detect,
)


class LSBDetectorGUI:
    """LSB 隐写检测 GUI 应用"""

    def __init__(self, root):
        self.root = root
        self.root.title("LSB 隐写检测工具")
        self.root.geometry("800x650")
        self.root.minsize(700, 550)

        # 当前加载的图像
        self.current_image = None
        self.current_path = None

        # 构建界面
        self._build_ui()

    def _build_ui(self):
        """构建 GUI 界面"""

        # ===== 顶部：文件选择区 =====
        file_frame = ttk.LabelFrame(self.root, text="图像文件", padding=10)
        file_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(file_frame, textvariable=self.path_var, state="readonly")
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        browse_btn = ttk.Button(file_frame, text="选择文件...", command=self._browse_file)
        browse_btn.pack(side=tk.RIGHT)

        # ===== 中部：检测方法选择 =====
        method_frame = ttk.LabelFrame(self.root, text="检测方法", padding=10)
        method_frame.pack(fill=tk.X, padx=10, pady=5)

        # 方法选择
        self.method_var = tk.StringVar(value="all")

        methods = [
            ("综合检测（推荐）", "all"),
            ("Chi-Square 分析", "chi"),
            ("RS 分析", "rs"),
            ("SPA 样本对分析", "spa"),
            ("视觉攻击（位平面提取）", "visual"),
        ]

        for i, (text, value) in enumerate(methods):
            rb = ttk.Radiobutton(method_frame, text=text, variable=self.method_var, value=value)
            rb.grid(row=i // 3, column=i % 3, sticky=tk.W, padx=10, pady=2)

        # 位平面选择（仅视觉攻击用）
        bit_frame = ttk.Frame(method_frame)
        bit_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W, padx=10, pady=(5, 0))

        ttk.Label(bit_frame, text="位平面:").pack(side=tk.LEFT)
        self.bit_var = tk.IntVar(value=0)
        bit_spin = ttk.Spinbox(bit_frame, from_=0, to=7, width=3, textvariable=self.bit_var)
        bit_spin.pack(side=tk.LEFT, padx=5)
        ttk.Label(bit_frame, text="(0=LSB, 7=MSB，仅视觉攻击使用)").pack(side=tk.LEFT)

        # ===== 操作按钮 =====
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        self.run_btn = ttk.Button(btn_frame, text="开始检测", command=self._run_detection)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.clear_btn = ttk.Button(btn_frame, text="清除结果", command=self._clear_results)
        self.clear_btn.pack(side=tk.LEFT)

        # 进度指示
        self.progress_var = tk.StringVar(value="就绪")
        progress_label = ttk.Label(btn_frame, textvariable=self.progress_var)
        progress_label.pack(side=tk.RIGHT)

        self.progress_bar = ttk.Progressbar(btn_frame, mode="indeterminate", length=120)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)

        # ===== 结果显示区 =====
        result_frame = ttk.LabelFrame(self.root, text="检测结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self.result_text = scrolledtext.ScrolledText(
            result_frame, wrap=tk.WORD, font=("Courier", 10), height=18
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # 设置文本标签样式
        self.result_text.tag_configure("title", font=("Courier", 12, "bold"))
        self.result_text.tag_configure("warning", foreground="#CC6600")
        self.result_text.tag_configure("danger", foreground="#CC0000", font=("Courier", 10, "bold"))
        self.result_text.tag_configure("safe", foreground="#006600")
        self.result_text.tag_configure("info", foreground="#0066CC")

        # ===== 状态栏 =====
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        ttk.Label(status_frame, text="支持格式: BMP (24-bit), PPM (P6)  |  提示: convert input.png output.bmp").pack(
            side=tk.LEFT
        )

    def _browse_file(self):
        """打开文件选择对话框"""
        filetypes = [
            ("支持的图像", "*.bmp *.ppm"),
            ("BMP 文件", "*.bmp"),
            ("PPM 文件", "*.ppm"),
            ("所有文件", "*.*"),
        ]
        filepath = filedialog.askopenfilename(title="选择图像文件", filetypes=filetypes)
        if filepath:
            self.path_var.set(filepath)
            self.current_path = filepath
            self._load_image(filepath)

    def _load_image(self, filepath):
        """加载图像"""
        try:
            self.current_image = load_image(filepath)
            self.progress_var.set(
                f"已加载: {self.current_image.width}x{self.current_image.height}, "
                f"{self.current_image.channels} 通道"
            )
        except Exception as e:
            messagebox.showerror("加载失败", f"无法加载图像:\n{str(e)}")
            self.current_image = None
            self.progress_var.set("加载失败")

    def _run_detection(self):
        """在后台线程运行检测"""
        if not self.current_image:
            messagebox.showwarning("提示", "请先选择一个图像文件")
            return

        # 禁用按钮，启动进度条
        self.run_btn.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        self.progress_var.set("正在检测...")

        # 后台线程执行检测
        thread = threading.Thread(target=self._detection_worker, daemon=True)
        thread.start()

    def _detection_worker(self):
        """检测工作线程"""
        method = self.method_var.get()

        try:
            if method == "all":
                result = self._run_comprehensive()
            elif method == "chi":
                result = self._run_chi_square()
            elif method == "rs":
                result = self._run_rs()
            elif method == "spa":
                result = self._run_spa()
            elif method == "visual":
                result = self._run_visual()
            else:
                result = "未知方法"

            # 在主线程更新 UI
            self.root.after(0, self._display_result, result)

        except Exception as e:
            self.root.after(0, self._display_error, str(e))

    def _run_comprehensive(self):
        """综合检测"""
        lines = []
        lines.append(("=" * 56 + "\n", "title"))
        lines.append(("  LSB 隐写检测综合报告\n", "title"))
        lines.append((f"  文件: {self.current_path}\n", "info"))
        lines.append((f"  尺寸: {self.current_image.width} x {self.current_image.height}\n", "info"))
        lines.append(("=" * 56 + "\n\n", "title"))

        # Chi-square
        lines.append(("[1] Chi-Square 分析\n", "info"))
        chi = chi_square_analysis(self.current_image)
        for k, v in chi.items():
            if k == "overall_suspicion":
                lines.append((f"    综合嫌疑度: {v:.2%}\n\n", self._score_tag(v)))
            else:
                lines.append((f"    {k}: ratio={v['ratio']}, 嫌疑度={v['suspicion']:.2%}\n", None))

        # RS
        lines.append(("[2] RS 分析\n", "info"))
        rs = rs_analysis(self.current_image)
        for k, v in rs.items():
            if k == "overall_embedding_rate":
                lines.append((f"    综合嵌入率估计: {v:.2%}\n\n", self._score_tag(v)))
            else:
                lines.append((
                    f"    {k}: R_m={v['R_m']}, S_m={v['S_m']}, 嵌入率≈{v['estimated_embedding_rate']:.2%}\n",
                    None
                ))

        # SPA
        lines.append(("[3] SPA 样本对分析\n", "info"))
        spa = spa_analysis(self.current_image)
        for k, v in spa.items():
            if k == "overall_suspicion":
                lines.append((f"    综合嫌疑度: {v:.2%}\n\n", self._score_tag(v)))
            else:
                lines.append((f"    {k}: 嵌入率估计={v['estimated_embedding']:.2%}\n", None))

        # 综合判定
        scores = [chi["overall_suspicion"], rs["overall_embedding_rate"], spa["overall_suspicion"]]
        overall = sum(scores) / len(scores)

        lines.append(("=" * 56 + "\n", "title"))
        lines.append((f"  综合检测得分: {overall:.2%}\n", self._score_tag(overall)))

        if overall > 0.7:
            verdict = "高度可疑 - 极可能存在 LSB 隐写"
            tag = "danger"
        elif overall > 0.4:
            verdict = "中度可疑 - 可能存在 LSB 隐写"
            tag = "warning"
        elif overall > 0.2:
            verdict = "低度可疑 - 不太可能存在隐写"
            tag = "safe"
        else:
            verdict = "正常 - 未检测到 LSB 隐写迹象"
            tag = "safe"

        lines.append((f"  判定: {verdict}\n", tag))
        lines.append(("=" * 56 + "\n", "title"))

        return lines

    def _run_chi_square(self):
        """Chi-Square 分析"""
        lines = []
        lines.append(("[Chi-Square 分析结果]\n\n", "title"))
        result = chi_square_analysis(self.current_image)
        for k, v in result.items():
            if k == "overall_suspicion":
                lines.append((f"\n综合嫌疑度: {v:.2%}\n", self._score_tag(v)))
            else:
                lines.append((f"{k} 通道:\n", "info"))
                lines.append((f"  Chi-Square 值: {v['chi_square']}\n", None))
                lines.append((f"  自由度: {v['dof']}\n", None))
                lines.append((f"  比率: {v['ratio']}\n", None))
                lines.append((f"  嫌疑度: {v['suspicion']:.2%}\n\n", self._score_tag(v['suspicion'])))
        return lines

    def _run_rs(self):
        """RS 分析"""
        lines = []
        lines.append(("[RS 分析结果]\n\n", "title"))
        result = rs_analysis(self.current_image)
        for k, v in result.items():
            if k == "overall_embedding_rate":
                lines.append((f"\n综合嵌入率估计: {v:.2%}\n", self._score_tag(v)))
            else:
                lines.append((f"{k} 通道:\n", "info"))
                lines.append((f"  R_m={v['R_m']}, S_m={v['S_m']}\n", None))
                lines.append((f"  R_-m={v['R_neg_m']}, S_-m={v['S_neg_m']}\n", None))
                lines.append((f"  嵌入率估计: {v['estimated_embedding_rate']:.2%}\n\n",
                              self._score_tag(v['estimated_embedding_rate'])))
        return lines

    def _run_spa(self):
        """SPA 分析"""
        lines = []
        lines.append(("[SPA 样本对分析结果]\n\n", "title"))
        result = spa_analysis(self.current_image)
        for k, v in result.items():
            if k == "overall_suspicion":
                lines.append((f"\n综合嫌疑度: {v:.2%}\n", self._score_tag(v)))
            else:
                lines.append((f"{k} 通道:\n", "info"))
                lines.append((f"  trace_same 比率: {v['trace_same_ratio']}\n", None))
                lines.append((f"  trace_diff1 比率: {v['trace_diff1_ratio']}\n", None))
                lines.append((f"  嵌入率估计: {v['estimated_embedding']:.2%}\n\n",
                              self._score_tag(v['estimated_embedding'])))
        return lines

    def _run_visual(self):
        """视觉攻击"""
        bit = self.bit_var.get()
        base, _ = os.path.splitext(self.current_path)
        output_path = f"{base}_lsb_plane{bit}.bmp"

        visual_attack(self.current_image, output_path, bit_plane=bit)

        lines = []
        lines.append(("[视觉攻击 - 位平面提取]\n\n", "title"))
        lines.append((f"提取位平面: {bit} ({'LSB' if bit == 0 else 'MSB' if bit == 7 else f'Bit {bit}'})\n", "info"))
        lines.append((f"输出文件: {output_path}\n\n", None))
        lines.append(("提示:\n", "info"))
        lines.append(("  如果输出图像中出现可辨认的文字、图案或有规律的结构，\n", None))
        lines.append(("  则说明该位平面被用于嵌入隐写信息。\n", None))
        lines.append(("  自然图像的 LSB 平面应该呈现随机噪声。\n", None))
        return lines

    def _score_tag(self, score):
        """根据分数返回颜色标签"""
        if score > 0.7:
            return "danger"
        elif score > 0.4:
            return "warning"
        else:
            return "safe"

    def _display_result(self, lines):
        """在结果区显示检测结果"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)

        for text, tag in lines:
            if tag:
                self.result_text.insert(tk.END, text, tag)
            else:
                self.result_text.insert(tk.END, text)

        self.result_text.config(state=tk.DISABLED)

        # 恢复 UI 状态
        self.progress_bar.stop()
        self.run_btn.config(state=tk.NORMAL)
        self.progress_var.set("检测完成")

    def _display_error(self, error_msg):
        """显示错误"""
        self.progress_bar.stop()
        self.run_btn.config(state=tk.NORMAL)
        self.progress_var.set("检测失败")
        messagebox.showerror("检测错误", f"检测过程中出错:\n{error_msg}")

    def _clear_results(self):
        """清除结果"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.progress_var.set("就绪")


def main():
    root = tk.Tk()

    # 设置主题样式
    style = ttk.Style()
    available_themes = style.theme_names()
    # 优先使用 clam 主题（跨平台较美观）
    if "clam" in available_themes:
        style.theme_use("clam")
    elif "alt" in available_themes:
        style.theme_use("alt")

    app = LSBDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
