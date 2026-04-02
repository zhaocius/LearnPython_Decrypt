# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct
import cv2
import numpy as np

def load_private_key(key_path):
    """从文件加载私钥"""
    try:
        with open(key_path, "rb") as f:
            key_data = f.read()
            print(f"私钥文件大小：{len(key_data)}字节")
            print(f"私钥文件内容（前100字节）：{key_data[:100].hex()}")
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            print("私钥加载成功")
            return private_key
    except Exception as e:
        print(f"加载私钥时出错：{e}")
        return None

def unpad_data(data):
    """移除PKCS7填充"""
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt_file(video_path, private_key, output_dir='output'):
    """从视频文件解密数据"""
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 打开视频文件
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print("错误：无法打开视频文件")
        return None
    
    # 检查视频尺寸
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    if width != 1920 or height != 1080:
        print(f"错误：视频尺寸不正确，期望1920x1080，实际{width}x{height}")
        return None
    
    # 获取总帧数
    num_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    print(f"总帧数：{num_frames}")
    
    # 读取所有帧
    frames_data = []
    total_size = 0
    frame_count = 0
    while frame_count < num_frames:
        ret, frame = cap.read()
        if not ret:
            print(f"错误：无法读取视频帧 {frame_count}")
            return None
        
        # 将帧转换为灰度图
        if len(frame.shape) == 3:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        # 将帧数据转换为字节
        frame_data = frame.tobytes()
        total_size += len(frame_data)
        frames_data.append(frame_data)
        print(f"已读取第{frame_count+1}帧，数据大小：{len(frame_data)}字节")
        frame_count += 1
    
    # 释放视频读取器
    cap.release()
    
    # 合并所有帧的数据
    combined_data = b''.join(frames_data)
    print(f"合并后的数据大小：{len(combined_data)}字节")
    
    try:
        # 分离数据
        data_length = struct.unpack(">I", combined_data[:4])[0]
        if data_length > len(combined_data) - 276:
            print("错误：数据长度无效")
            return None
        
        iv = bytes(combined_data[4:20])
        if len(iv) != 16:
            print("错误：IV长度无效")
            return None
        
        encrypted_aes_key = bytes(combined_data[20:276])
        if len(encrypted_aes_key) != 256:
            print("错误：加密的AES密钥长度无效")
            return None
        
        encrypted_data = bytes(combined_data[276:276+data_length])
        if len(encrypted_data) != data_length:
            print("错误：加密的文件数据长度无效")
            return None
        
        print(f"数据长度：{data_length}")
        print(f"IV长度：{len(iv)}")
        print(f"加密的AES密钥长度：{len(encrypted_aes_key)}")
        print(f"加密的文件数据长度：{len(encrypted_data)}")
        print(f"总数据大小：{len(combined_data)}字节")
        
        # 使用RSA解密AES密钥
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"解密AES密钥时出错：{e}")
            print(f"加密的AES密钥（十六进制）：{encrypted_aes_key.hex()}")
            return None
        
        # 使用AES解密文件数据
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # 解密数据并移除填充
        try:
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            decrypted_data = unpad_data(decrypted_data)
        except Exception as e:
            print(f"解密文件数据时出错：{e}")
            return None
        
        # 保存解密后的文件
        output_path = os.path.join(output_dir, "test.zip")
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        
        return output_path
    except Exception as e:
        print(f"处理数据时出错：{e}")
        return None

def main():
    # 检查密钥文件是否存在
    key_path = "private_key.pem"  # 从当前目录读取私钥
    if not os.path.exists(key_path):
        print("错误：找不到私钥文件，请确保私钥文件在当前目录下")
        return
    
    # 加载私钥
    private_key = load_private_key(key_path)
    if private_key is None:
        print("错误：无法加载私钥")
        return
    print("已加载私钥")
    
    # 检查加密视频文件是否存在
    video_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "encryption", "output", "encrypted.avi")
    if not os.path.exists(video_path):
        print("错误：找不到加密视频文件，请先运行加密程序")
        return
    
    # 解密视频文件
    decrypted_file = decrypt_file(video_path, private_key)
    print("已解密视频文件并保存为文件: {}".format(decrypted_file))

if __name__ == "__main__":
    main() 