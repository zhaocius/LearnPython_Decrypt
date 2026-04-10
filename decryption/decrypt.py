# -*- coding: utf-8 -*-
"""
解密模块 - 从隐写视频恢复原始文件
独立运行，不依赖 encryption 目录
"""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import argparse

# 导入本地提取模块
from extract import (
    extract_all_data_from_video,
    extract_header_from_video,
    HEADER_SIZE
)

def load_private_key(key_path: str):
    """
    从PEM文件加载RSA私钥
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"私钥文件不存在: {key_path}")

    with open(key_path, "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
        backend=default_backend()
    )
    print(f"私钥加载成功: {key_path}")
    return private_key

def decrypt_aes_key(encrypted_aes_key: bytes, private_key) -> bytes:
    """
    使用RSA私钥解密AES密钥（OAEP填充）
    """
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def unpad_pkcs7(data: bytes) -> bytes:
    """
    移除PKCS7填充
    """
    padding_length = data[-1]
    if padding_length > 16 or padding_length == 0:
        raise ValueError("无效的PKCS7填充")

    # 验证填充
    for i in range(padding_length):
        if data[-(i + 1)] != padding_length:
            raise ValueError("PKCS7填充验证失败")

    return data[:-padding_length]

def decrypt_data(encrypted_data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """
    使用AES-256-CBC解密数据
    """
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    # 移除PKCS7填充
    decrypted_data = unpad_pkcs7(decrypted_padded)
    return decrypted_data

def decrypt_video(
    video_path: str,
    private_key_path: str,
    output_path: str = None,
    output_dir: str = 'output'
) -> str:
    """
    解密视频中的隐藏数据，恢复原始文件
    参数：
        video_path: 隐写视频文件路径
        private_key_path: RSA私钥文件路径
        output_path: 输出文件路径（可选）
        output_dir: 输出目录（默认 'output'）
    返回：
        解密后的文件路径
    """
    # 加载私钥
    private_key = load_private_key(private_key_path)

    # 从视频提取头部
    encrypted_aes_key, iv, encrypted_data_size, is_valid = extract_header_from_video(video_path)

    if not is_valid:
        raise ValueError("视频中未找到有效嵌入数据（魔数不匹配）")

    print(f"提取头部成功：加密数据大小 {encrypted_data_size} 字节")

    # 解密AES密钥
    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    print("AES密钥解密成功")

    # 提取完整数据
    full_data = extract_all_data_from_video(video_path)

    # 提取加密数据部分
    encrypted_data = full_data[HEADER_SIZE:HEADER_SIZE + encrypted_data_size]

    # 解密数据
    decrypted_data = decrypt_data(encrypted_data, aes_key, iv)
    print(f"数据解密成功：原始大小 {len(decrypted_data)} 字节")

    # 确定输出路径
    if output_path is None:
        os.makedirs(output_dir, exist_ok=True)
        # 根据视频文件名推断输出文件名
        video_name = os.path.splitext(os.path.basename(video_path))[0]
        output_path = os.path.join(output_dir, f'{video_name}.zip')

    # 写入文件
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    print(f"文件已保存至: {output_path}")

    return output_path

def main():
    """CLI入口"""
    parser = argparse.ArgumentParser(
        description='从隐写视频解密恢复原始文件',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python decrypt.py video.avi private_key.pem
  python decrypt.py video.avi private_key.pem -o recovered.zip
  python decrypt.py video.avi private_key.pem -d my_output/
        '''
    )
    parser.add_argument('video', help='隐写视频文件路径')
    parser.add_argument('private_key', nargs='?', default='private_key.pem',
                        help='RSA私钥文件路径（默认: private_key.pem）')
    parser.add_argument('-o', '--output', help='输出文件路径', default=None)
    parser.add_argument('-d', '--output-dir', default='output',
                        help='输出目录（默认: output）')

    args = parser.parse_args()

    # 处理路径
    decryption_dir = os.path.dirname(os.path.abspath(__file__))
    private_key_path = args.private_key
    if not os.path.isabs(private_key_path):
        private_key_path = os.path.join(decryption_dir, private_key_path)

    try:
        output_path = decrypt_video(
            args.video,
            private_key_path,
            args.output,
            args.output_dir
        )
        print(f"\n解密完成！文件保存至: {output_path}")
        return 0
    except FileNotFoundError as e:
        print(f"\n错误: {e}")
        return 1
    except Exception as e:
        print(f"\n解密失败: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())