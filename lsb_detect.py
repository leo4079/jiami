# LSB Steganography Detection Tool (Pure Python - No Dependencies)
# 支持 BMP 和 PPM 格式图像（无需第三方库）

"""
LSB (Least Significant Bit) 隐写检测工具
纯 Python 实现，无需安装任何第三方包。

支持检测方法：
1. Chi-square 分析 - 统计检测 LSB 替换
2. RS 分析 - Regular/Singular 分组检测
3. 视觉攻击 - 提取最低位生成可视化图像
4. SPA 样本对分析 - Sample Pair Analysis

支持格式：BMP (24-bit), PPM (P6 binary)
"""

import sys
import os
import struct
import math
import random


# ===== Image I/O (Pure Python) =====

class RawImage:
    """简单的图像容器"""
    def __init__(self, width, height, channels, data):
        self.width = width
        self.height = height
        self.channels = channels
        # data: flat list of pixel values, row by row, channel by channel per pixel
        # [R, G, B, R, G, B, ...]
        self.data = data

    def get_pixel(self, x, y):
        """获取 (x, y) 处的像素值列表 [R, G, B]"""
        idx = (y * self.width + x) * self.channels
        return self.data[idx:idx + self.channels]

    def get_channel(self, ch):
        """获取单通道的所有像素值"""
        return self.data[ch::self.channels]


def load_bmp(filepath):
    """读取 24-bit BMP 文件"""
    with open(filepath, 'rb') as f:
        # BMP Header
        header = f.read(14)
        if header[:2] != b'BM':
            raise ValueError("不是有效的 BMP 文件")

        data_offset = struct.unpack_from('<I', header, 10)[0]

        # DIB Header
        dib_header = f.read(40)
        width = struct.unpack_from('<i', dib_header, 4)[0]
        height = struct.unpack_from('<i', dib_header, 8)[0]
        bits_per_pixel = struct.unpack_from('<H', dib_header, 14)[0]

        if bits_per_pixel != 24:
            raise ValueError(f"仅支持 24-bit BMP，当前为 {bits_per_pixel}-bit")

        # BMP 行对齐到 4 字节
        row_size = ((width * 3 + 3) // 4) * 4
        bottom_up = height > 0
        height = abs(height)

        f.seek(data_offset)
        pixels = []

        for row in range(height):
            row_data = f.read(row_size)
            for col in range(width):
                b = row_data[col * 3]
                g = row_data[col * 3 + 1]
                r = row_data[col * 3 + 2]
                pixels.append((r, g, b))

        # BMP 默认自底向上存储
        if bottom_up:
            rows = [pixels[i * width:(i + 1) * width] for i in range(height)]
            rows.reverse()
            pixels = []
            for row in rows:
                pixels.extend(row)

        # 展开为 flat list
        flat = []
        for r, g, b in pixels:
            flat.extend([r, g, b])

        return RawImage(width, height, 3, flat)


def load_ppm(filepath):
    """读取 PPM (P6) 文件"""
    with open(filepath, 'rb') as f:
        magic = f.readline().strip()
        if magic != b'P6':
            raise ValueError("仅支持 P6 (binary) PPM 格式")

        # 跳过注释
        line = f.readline()
        while line.startswith(b'#'):
            line = f.readline()

        parts = line.split()
        width = int(parts[0])
        height = int(parts[1])

        maxval_line = f.readline().strip()
        maxval = int(maxval_line)

        if maxval > 255:
            raise ValueError("仅支持 8-bit PPM")

        data = f.read(width * height * 3)
        flat = list(data)

        return RawImage(width, height, 3, flat)


def load_image(filepath):
    """自动检测格式并加载图像"""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == '.bmp':
        return load_bmp(filepath)
    elif ext in ('.ppm', '.pgm'):
        return load_ppm(filepath)
    else:
        # 尝试读取文件头判断
        with open(filepath, 'rb') as f:
            header = f.read(2)
        if header == b'BM':
            return load_bmp(filepath)
        elif header in (b'P6', b'P5'):
            return load_ppm(filepath)
        else:
            raise ValueError(
                f"不支持的格式: {ext}\n"
                "支持的格式: BMP (24-bit), PPM (P6)\n"
                "提示: 可用 ImageMagick 转换: convert input.png output.bmp"
            )


def save_bmp(image, filepath):
    """保存为 24-bit BMP"""
    width, height, channels = image.width, image.height, image.channels
    row_size = ((width * 3 + 3) // 4) * 4
    padding = row_size - width * 3
    pixel_data_size = row_size * height
    file_size = 54 + pixel_data_size

    with open(filepath, 'wb') as f:
        # File Header
        f.write(b'BM')
        f.write(struct.pack('<I', file_size))
        f.write(struct.pack('<HH', 0, 0))
        f.write(struct.pack('<I', 54))

        # DIB Header (BITMAPINFOHEADER)
        f.write(struct.pack('<I', 40))
        f.write(struct.pack('<i', width))
        f.write(struct.pack('<i', height))  # bottom-up
        f.write(struct.pack('<HH', 1, 24))
        f.write(struct.pack('<I', 0))  # no compression
        f.write(struct.pack('<I', pixel_data_size))
        f.write(struct.pack('<i', 2835))  # 72 DPI
        f.write(struct.pack('<i', 2835))
        f.write(struct.pack('<I', 0))
        f.write(struct.pack('<I', 0))

        # Pixel data (bottom-up)
        for row in range(height - 1, -1, -1):
            for col in range(width):
                idx = (row * width + col) * channels
                if channels >= 3:
                    r, g, b = image.data[idx], image.data[idx + 1], image.data[idx + 2]
                else:
                    r = g = b = image.data[idx]
                f.write(bytes([b, g, r]))
            f.write(b'\x00' * padding)


# ===== 1. Chi-Square Analysis =====
def chi_square_analysis(image):
    """
    Chi-square 分析：检测像素值对(2i, 2i+1)的分布是否异常均匀。
    LSB 隐写会使相邻像素值对的频率趋于相等。
    """
    results = {}
    channel_names = ['R', 'G', 'B']

    for ch in range(image.channels):
        channel_data = image.get_channel(ch)

        # 统计直方图
        histogram = [0] * 256
        for val in channel_data:
            histogram[val] += 1

        # Chi-square 统计量
        chi_sq = 0.0
        pairs_count = 0

        for i in range(0, 256, 2):
            expected = (histogram[i] + histogram[i + 1]) / 2.0
            if expected > 0:
                chi_sq += ((histogram[i] - expected) ** 2) / expected
                chi_sq += ((histogram[i + 1] - expected) ** 2) / expected
                pairs_count += 1

        dof = max(pairs_count - 1, 1)
        ratio = chi_sq / dof

        # ratio 接近 1 → 高度可疑（LSB 替换使分布均匀）
        # ratio >> 1 → 正常图像
        if ratio < 1.5:
            suspicion = min(1.0, max(0.0, 1.0 - (ratio - 0.8) / 0.7))
        else:
            suspicion = max(0.0, 1.0 - (ratio - 1.0) / 5.0)

        suspicion = max(0.0, min(1.0, suspicion))

        results[channel_names[ch]] = {
            'chi_square': round(chi_sq, 2),
            'dof': dof,
            'ratio': round(ratio, 4),
            'suspicion': round(suspicion, 4)
        }

    avg_suspicion = sum(r['suspicion'] for r in results.values()) / len(results)
    results['overall_suspicion'] = round(avg_suspicion, 4)

    return results


# ===== 2. RS Analysis =====
def rs_analysis(image, sample_size=10000):
    """
    RS (Regular-Singular) 分析：
    通过正/负翻转操作统计 Regular 和 Singular 组的比例。
    """
    results = {}
    channel_names = ['R', 'G', 'B']
    mask = [0, 1, 1, 0]
    group_size = len(mask)

    for ch in range(image.channels):
        channel_data = image.get_channel(ch)

        # 分组
        n = (len(channel_data) // group_size) * group_size
        channel_data = channel_data[:n]

        num_groups = n // group_size
        actual_sample = min(sample_size, num_groups)

        # 随机采样组索引
        if num_groups <= sample_size:
            indices = list(range(num_groups))
        else:
            random.seed(42)
            indices = random.sample(range(num_groups), actual_sample)

        r_m, s_m, r_neg_m, s_neg_m = 0, 0, 0, 0

        for idx in indices:
            start = idx * group_size
            group = channel_data[start:start + group_size]

            # 计算 discrimination（相邻差绝对值之和）
            d_orig = sum(abs(group[i + 1] - group[i]) for i in range(group_size - 1))

            # 正向翻转
            flipped_pos = list(group)
            for i, m in enumerate(mask):
                if m == 1:
                    flipped_pos[i] = flipped_pos[i] ^ 1
            d_pos = sum(abs(flipped_pos[i + 1] - flipped_pos[i]) for i in range(group_size - 1))

            if d_pos > d_orig:
                r_m += 1
            elif d_pos < d_orig:
                s_m += 1

            # 负向翻转
            flipped_neg = list(group)
            for i, m in enumerate(mask):
                if m == 1:
                    if flipped_neg[i] % 2 == 0:
                        flipped_neg[i] += 1
                    else:
                        flipped_neg[i] -= 1
                    flipped_neg[i] = flipped_neg[i] ^ 1
            d_neg = sum(abs(flipped_neg[i + 1] - flipped_neg[i]) for i in range(group_size - 1))

            if d_neg > d_orig:
                r_neg_m += 1
            elif d_neg < d_orig:
                s_neg_m += 1

        total = actual_sample
        r_m_ratio = r_m / total
        s_m_ratio = s_m / total
        r_neg_m_ratio = r_neg_m / total
        s_neg_m_ratio = s_neg_m / total

        diff_positive = abs(r_m_ratio - s_m_ratio)
        diff_negative = abs(r_neg_m_ratio - s_neg_m_ratio)

        if diff_negative > 0.001:
            embedding_rate = 1.0 - (diff_positive / diff_negative)
        else:
            embedding_rate = 0.0

        embedding_rate = max(0.0, min(1.0, embedding_rate))

        results[channel_names[ch]] = {
            'R_m': round(r_m_ratio, 4),
            'S_m': round(s_m_ratio, 4),
            'R_neg_m': round(r_neg_m_ratio, 4),
            'S_neg_m': round(s_neg_m_ratio, 4),
            'estimated_embedding_rate': round(embedding_rate, 4)
        }

    avg_rate = sum(r['estimated_embedding_rate'] for r in results.values()) / len(results)
    results['overall_embedding_rate'] = round(avg_rate, 4)

    return results


# ===== 3. Visual Attack =====
def visual_attack(image, output_path, bit_plane=0):
    """
    视觉攻击：提取指定位平面生成可视化 BMP 图像。
    如果最低位呈现有意义的图案，则存在隐写。
    """
    bit_mask = 1 << bit_plane
    new_data = []

    for val in image.data:
        # 提取指定位并放大到 0/255
        bit_val = ((val & bit_mask) >> bit_plane) * 255
        new_data.append(bit_val)

    result = RawImage(image.width, image.height, image.channels, new_data)
    save_bmp(result, output_path)
    print(f"[+] 位平面 {bit_plane} 可视化已保存 -> {output_path}")
    return output_path


# ===== 4. SPA Analysis =====
def spa_analysis(image):
    """
    样本对分析 (SPA)：
    基于 Dumitrescu/Wu/Wang 的方法。
    统计相邻像素对中 (u, v) 满足特定条件的数量：
    - D: |u-v| 在 LSB 翻转前后的变化
    使用闭合式公式估算嵌入率 p。
    """
    results = {}
    channel_names = ['R', 'G', 'B']

    for ch in range(image.channels):
        width = image.width
        height = image.height

        # 统计像素对 (u, v) - 水平相邻
        # 分类：
        # X: u//2 == v//2 (同一对值, 如 (4,5) 或 (100,101))
        # Y: u//2 == v//2 且 u != v
        # Z: 剩余

        # 使用简化的 SPA：统计 trace pairs
        # 对于每个水平相邻像素对 (u, v):
        # 如果 floor(u/2) == floor(v/2): 这是 "close pair"
        # LSB 嵌入会增加 close pairs 的数量

        close_pairs = 0
        total_pairs = 0

        # 同时统计 |u-v|=1 且 floor(u/2)==floor(v/2) 的对
        trace_same = 0  # u,v 在同一 "bin" (floor(u/2)==floor(v/2))
        trace_diff_1 = 0  # |floor(u/2) - floor(v/2)| == 1

        for row in range(height):
            for col in range(width - 1):
                idx1 = (row * width + col) * image.channels + ch
                idx2 = (row * width + col + 1) * image.channels + ch
                u = image.data[idx1]
                v = image.data[idx2]

                total_pairs += 1

                bin_u = u >> 1  # floor(u/2)
                bin_v = v >> 1  # floor(v/2)

                if bin_u == bin_v:
                    trace_same += 1
                elif abs(bin_u - bin_v) == 1:
                    trace_diff_1 += 1

        # 在自然图像中，trace_same 相对较少
        # LSB 嵌入后，一些 trace_diff_1 的对会变成 trace_same
        # 估算嵌入率
        if total_pairs > 0:
            ratio_same = trace_same / total_pairs
            ratio_diff1 = trace_diff_1 / total_pairs

            # 理论上，嵌入率 p 时：
            # E[trace_same_after] = trace_same_orig + p * trace_diff_1_orig / 2
            # 对于自然图像 ratio_same 通常 < ratio_diff1
            # 如果 ratio_same > ratio_diff1 * 0.5，可能有隐写

            if ratio_diff1 > 0:
                # 简化估算
                estimated_p = max(0, 2 * (ratio_same - ratio_diff1 * 0.3) / ratio_diff1)
                estimated_p = min(1.0, estimated_p)
            else:
                estimated_p = 0.0
        else:
            estimated_p = 0.0
            ratio_same = 0
            ratio_diff1 = 0

        results[channel_names[ch]] = {
            'trace_same_ratio': round(ratio_same, 4),
            'trace_diff1_ratio': round(ratio_diff1, 4),
            'estimated_embedding': round(estimated_p, 4)
        }

    avg_embedding = sum(r['estimated_embedding'] for r in results.values()) / len(results)
    results['overall_suspicion'] = round(avg_embedding, 4)

    return results


# ===== 5. Comprehensive Detection =====
def detect(image_path, output_visual=True):
    """综合检测：运行所有方法并输出报告。"""

    print(f"\n{'='*60}")
    print(f"  LSB 隐写检测报告")
    print(f"  目标文件: {image_path}")
    print(f"{'='*60}\n")

    image = load_image(image_path)
    print(f"  图像尺寸: {image.width} x {image.height}, {image.channels} 通道\n")

    report = {}

    # Chi-square
    print("[*] 正在执行 Chi-square 分析...")
    chi_result = chi_square_analysis(image)
    report['chi_square'] = chi_result
    print(f"    综合嫌疑度: {chi_result['overall_suspicion']:.2%}")
    for k, v in chi_result.items():
        if k != 'overall_suspicion':
            print(f"    {k} 通道: ratio={v['ratio']}, 嫌疑度={v['suspicion']:.2%}")
    print()

    # RS Analysis
    print("[*] 正在执行 RS 分析...")
    rs_result = rs_analysis(image)
    report['rs_analysis'] = rs_result
    print(f"    综合嵌入率估计: {rs_result['overall_embedding_rate']:.2%}")
    for k, v in rs_result.items():
        if k != 'overall_embedding_rate':
            print(f"    {k} 通道: R_m={v['R_m']}, S_m={v['S_m']}, 嵌入率≈{v['estimated_embedding_rate']:.2%}")
    print()

    # SPA
    print("[*] 正在执行 SPA 分析...")
    spa_result = spa_analysis(image)
    report['spa'] = spa_result
    print(f"    综合嫌疑度: {spa_result['overall_suspicion']:.2%}")
    for k, v in spa_result.items():
        if k != 'overall_suspicion':
            print(f"    {k} 通道: 嵌入率估计={v['estimated_embedding']:.2%}")
    print()

    # Visual Attack
    if output_visual:
        print("[*] 正在生成视觉攻击图像...")
        base, _ = os.path.splitext(image_path)
        visual_path = f"{base}_lsb_plane0.bmp"
        visual_attack(image, visual_path, bit_plane=0)
        report['visual_attack'] = visual_path
    print()

    # 综合判定
    scores = [
        chi_result['overall_suspicion'],
        rs_result['overall_embedding_rate'],
        spa_result['overall_suspicion']
    ]
    overall_score = sum(scores) / len(scores)
    report['overall_score'] = round(overall_score, 4)

    print(f"{'='*60}")
    print(f"  综合检测得分: {overall_score:.2%}")
    if overall_score > 0.7:
        verdict = "高度可疑 - 极可能存在 LSB 隐写"
    elif overall_score > 0.4:
        verdict = "中度可疑 - 可能存在 LSB 隐写"
    elif overall_score > 0.2:
        verdict = "低度可疑 - 不太可能存在隐写"
    else:
        verdict = "正常 - 未检测到 LSB 隐写迹象"

    report['verdict'] = verdict
    print(f"  判定结果: {verdict}")
    print(f"{'='*60}\n")

    return report


# ===== CLI =====
def main():
    if len(sys.argv) < 2:
        print("LSB 隐写检测工具 (纯 Python，无需安装依赖)")
        print("=" * 50)
        print("\n用法:")
        print("  python lsb_detect.py <image.bmp>              # 综合检测")
        print("  python lsb_detect.py <image.bmp> chi          # Chi-square 分析")
        print("  python lsb_detect.py <image.bmp> rs           # RS 分析")
        print("  python lsb_detect.py <image.bmp> spa          # SPA 分析")
        print("  python lsb_detect.py <image.bmp> visual [bit] # 视觉攻击 (bit=0~7)")
        print("\n支持格式: BMP (24-bit), PPM (P6)")
        print("提示: 可用 ffmpeg/ImageMagick 将 PNG/JPG 转为 BMP:")
        print("  convert input.png output.bmp")
        print("  ffmpeg -i input.png output.bmp")
        return

    image_path = sys.argv[1]

    if not os.path.exists(image_path):
        print(f"[!] 文件不存在: {image_path}")
        return

    if len(sys.argv) >= 3:
        method = sys.argv[2].lower()
        image = load_image(image_path)

        if method == 'chi':
            result = chi_square_analysis(image)
            print("\n[Chi-Square 分析结果]")
            for k, v in result.items():
                print(f"  {k}: {v}")
        elif method == 'rs':
            result = rs_analysis(image)
            print("\n[RS 分析结果]")
            for k, v in result.items():
                print(f"  {k}: {v}")
        elif method == 'spa':
            result = spa_analysis(image)
            print("\n[SPA 分析结果]")
            for k, v in result.items():
                print(f"  {k}: {v}")
        elif method == 'visual':
            bit = int(sys.argv[3]) if len(sys.argv) > 3 else 0
            base, _ = os.path.splitext(image_path)
            output = f"{base}_lsb_plane{bit}.bmp"
            visual_attack(image, output, bit_plane=bit)
        else:
            print(f"[!] 未知方法: {method}")
            print("    可用方法: chi, rs, spa, visual")
    else:
        detect(image_path)


if __name__ == '__main__':
    main()
