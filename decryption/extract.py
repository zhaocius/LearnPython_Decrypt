# -*- coding: utf-8 -*-
"""
视频数据提取模块 - 从隐写视频提取嵌入数据
独立模块，不依赖 encryption 目录
"""
import cv2
import numpy as np
import struct

# 常量定义（与加密时保持一致）
MAGIC_NUMBER = b'STEG'
HEADER_SIZE = 4 + 8 + 256 + 16  # 魔数(4) + 数据大小(8) + 加密密钥(256) + IV(16)

def parse_header(data: bytes) -> tuple:
    """
    解析嵌入数据头部
    返回：(encrypted_aes_key, iv, encrypted_data_size, is_valid)
    """
    if len(data) < HEADER_SIZE:
        return None, None, 0, False

    magic = data[:4]
    if magic != MAGIC_NUMBER:
        return None, None, 0, False

    encrypted_data_size = struct.unpack('>Q', data[4:12])[0]
    encrypted_aes_key = data[12:268]
    iv = data[268:284]

    return encrypted_aes_key, iv, encrypted_data_size, True

def extract_data_lsb(frames: np.ndarray, expected_size: int) -> bytes:
    """
    从视频帧使用LSB方法提取嵌入数据
    参数：
        frames: 视频帧数组 (num_frames, height, width, 3)
        expected_size: 预期提取的数据字节大小
    返回：
        提取的二进制数据
    """
    total_bits = expected_size * 8
    bits = []

    bit_index = 0
    for frame_idx in range(frames.shape[0]):
        for row in range(frames.shape[1]):
            for col in range(frames.shape[2]):
                for channel in range(frames.shape[3]):
                    if bit_index >= total_bits:
                        break
                    # 提取LSB
                    bit = frames[frame_idx, row, col, channel] & 1
                    bits.append(bit)
                    bit_index += 1

    # 将位序列转换为字节
    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
        data.append(byte)

    return bytes(data)

def load_video_frames(video_path: str) -> tuple:
    """
    加载视频的所有帧
    返回：(frames数组, fps, width, height)
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"无法打开视频文件: {video_path}")

    fps = int(cap.get(cv2.CAP_PROP_FPS))
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    frames = []
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frames.append(frame)
    cap.release()

    if len(frames) == 0:
        raise ValueError("视频中没有帧数据")

    return np.array(frames), fps, width, height

def extract_header_from_video(video_path: str) -> tuple:
    """
    从视频文件提取头部信息
    返回：(encrypted_aes_key, iv, encrypted_data_size, is_valid)
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"无法打开视频文件: {video_path}")

    # 读取第一帧提取头部
    ret, frame = cap.read()
    cap.release()

    if not ret:
        raise ValueError("无法读取视频帧")

    # 从第一帧提取头部数据
    header_bits_needed = HEADER_SIZE * 8
    bits = []

    frame_height = frame.shape[0]
    frame_width = frame.shape[1]
    frame_channels = frame.shape[2]

    bit_index = 0
    for row in range(frame_height):
        for col in range(frame_width):
            for channel in range(frame_channels):
                if bit_index >= header_bits_needed:
                    break
                bit = frame[row, col, channel] & 1
                bits.append(bit)
                bit_index += 1

    # 转换为字节
    header_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
        header_bytes.append(byte)

    return parse_header(bytes(header_bytes))

def extract_all_data_from_video(video_path: str) -> bytes:
    """
    从视频文件提取所有嵌入数据
    返回：
        提取的完整数据（包含头部和加密数据）
    """
    # 首先提取头部获取数据大小
    encrypted_aes_key, iv, encrypted_data_size, is_valid = extract_header_from_video(video_path)

    if not is_valid:
        raise ValueError("视频中未找到有效嵌入数据（魔数不匹配）")

    # 总数据大小 = 头部 + 加密数据
    total_data_size = HEADER_SIZE + encrypted_data_size

    # 加载所有帧
    frames, _, _, _ = load_video_frames(video_path)

    # 提取完整数据
    data = extract_data_lsb(frames, total_data_size)

    return data