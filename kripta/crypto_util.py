#!/usr/bin/env python3
# ОПТИМИЗАЦИЯ, ТЕСТЫ, ВРЕМЯ, ЛОГИ ПРИ НЕВЕРНОМ ПАРОЛЕ
import os
import sys
import argparse
import random
import hashlib
import shutil
import json
import time
import ctypes
from ctypes import wintypes
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import struct
import psutil
import datetime

BLOCK_SIZE = 16 * 1024  # 16 KB
LOG_FILE = "crypto_log.log"

def get_cursor_position():
    """Get current cursor position using Windows API"""
    cursor = wintypes.POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(cursor))
    return cursor.x, cursor.y

def save_key(key: bytes, iv: bytes, output_file: str):
    """Save key and IV to a file"""
    key_data = {
        'key': ''.join(f'{b:02X}' for b in key),
        'iv': ''.join(f'{b:02X}' for b in iv)
    }
    with open(output_file, 'w') as f:
        json.dump(key_data, f)

def load_key(input_file: str) -> tuple[bytes, bytes]:
    """Load key and IV from a file"""
    try:
        with open(input_file, 'r') as f:
            key_data = json.load(f)
        key = bytes.fromhex(key_data['key'])
        iv = bytes.fromhex(key_data['iv'])
        return key, iv
    except Exception:
        raise ValueError("Ошибка: неверный ключ или повреждённый файл ключа")

def generate_key_from_mouse():
    """Generate encryption key and IV from mouse movements"""
    ENTROPY_POOL_SIZE = 32  # Увеличиваем размер для AES-256
    entropy_pool = bytearray(ENTROPY_POOL_SIZE)
    current_size = 0
    
    last_x, last_y = get_cursor_position()
    
    print("Двигайте мышью для генерации ключа...")
    while current_size < ENTROPY_POOL_SIZE:
        x, y = get_cursor_position()
        
        if x != last_x or y != last_y:
            delta_x = x - last_x
            delta_y = y - last_y
            
            # Ограничиваем значения в диапазоне 0-255
            delta_x = max(-255, min(255, delta_x))
            delta_y = max(-255, min(255, delta_y))
            
            # XOR с временем для дополнительной энтропии
            value = (delta_x ^ delta_y) ^ (int(time.time() * 1000) & 0xFF)
            entropy_pool[current_size % ENTROPY_POOL_SIZE] ^= value & 0xFF
            current_size += 1
            
            last_x, last_y = x, y
        
        time.sleep(0.01)
    
    # Используем первые 16 байт для ключа и следующие 16 для IV
    key = bytes(entropy_pool[:16])
    iv = bytes(entropy_pool[16:32])
    
    # Выводим ключ и вектор в шестнадцатеричном формате
    print("\nСгенерированный ключ (hex):")
    print(''.join(f'{b:02X}' for b in key))
    print("\nСгенерированный вектор инициализации (hex):")
    print(''.join(f'{b:02X}' for b in iv))
    print()
    
    return key, iv

def encrypt_metadata(metadata: dict, key: bytes, iv: bytes) -> bytes:
    """
    Шифрует метаданные (словарь) с помощью AES и возвращает:
    [4 байта длины][зашифрованные метаданные]
    """
    metadata_json = json.dumps(metadata).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(metadata_json, AES.block_size)
    encrypted = cipher.encrypt(padded)
    # Сохраняем длину зашифрованных метаданных (4 байта big-endian)
    return struct.pack('>I', len(encrypted)) + encrypted

def decrypt_metadata(data: bytes, key: bytes, iv: bytes) -> tuple[dict, int]:
    """
    Расшифровывает метаданные из начала файла.
    Возвращает словарь метаданных и количество байт, занятых метаданными.
    """
    try:
        length = struct.unpack('>I', data[:4])[0]
        encrypted = data[4:4+length]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        metadata = json.loads(decrypted.decode('utf-8'))
        return metadata, 4 + length
    except Exception:
        raise ValueError('Ошибка: неверный ключ или повреждённый файл (метаданные не расшифрованы)')

def encrypt_file(input_file: str, output_file: str, key: bytes, iv: bytes, log_file: str) -> None:
    """
    Шифрует файл только с помощью AES (без дополнительных шагов).
    """
    try:
        input_path = Path(input_file)
        metadata = {
            'original_name': input_path.name,
            'extension': input_path.suffix,
            'size': input_path.stat().st_size,
            'created_time': input_path.stat().st_ctime,
            'modified_time': input_path.stat().st_mtime
        }
        meta_encrypted = encrypt_metadata(metadata, key, iv)
        with open(input_file, 'rb') as file:
            data = file.read()
        start = time.time()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        elapsed = time.time() - start
        with open(output_file, 'wb') as file:
            file.write(meta_encrypted + encrypted_data)
        mb = len(data) / (1024 * 1024)
        speed = mb / elapsed if elapsed > 0 else 0
        log_message(f"[ENCRYPT] {input_file}: {mb:.2f} MB за {elapsed:.2f} сек ({speed:.2f} MB/s)", log_file)
    except Exception as e:
        log_message(f"Error encrypting file {input_file}: {str(e)}", log_file)
        raise

def decrypt_file(input_file: str, output_dir: str, key: bytes, iv: bytes, log_file: str) -> bool:
    """
    Дешифрует файл только с помощью AES (без дополнительных шагов).
    Возвращает True при успехе, False при ошибке.
    """
    try:
        with open(input_file, 'rb') as file:
            data = file.read()
        start = time.time()
        try:
            metadata, meta_len = decrypt_metadata(data, key, iv)
        except ValueError as ve:
            log_message(f"Error decrypting file {input_file}: {ve}", log_file)
            return False
        encrypted_data = data[meta_len:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except Exception:
            log_message(f"Error decrypting file {input_file}: Ошибка: неверный ключ или повреждённый файл (данные не расшифрованы)", log_file)
            return False
        elapsed = time.time() - start
        output_file = Path(output_dir) / metadata['original_name']
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        os.utime(output_file, (metadata['created_time'], metadata['modified_time']))
        mb = len(decrypted_data) / (1024 * 1024)
        speed = mb / elapsed if elapsed > 0 else 0
        log_message(f"[DECRYPT] {input_file}: {mb:.2f} MB за {elapsed:.2f} сек ({speed:.2f} MB/s)", log_file)
        return True
    except Exception as e:
        log_message(f"Error decrypting file {input_file}: {str(e)}", log_file)
        return False

def process_directory(input_dir: str, output_dir: str, key: bytes, iv: bytes, mode: str, log_file: str) -> None:
    """
    Рекурсивно обрабатывает все файлы и папки:
    - При шифровании: спрашивает имя для каждого зашифрованного файла
    - При расшифровке: восстанавливает оригинальное имя из метаданных
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    success_count = 0
    for item in input_path.iterdir():
        if item.is_file():
            try:
                log_message(f"\nProcessing file: {item}", log_file)
                if mode == 'encrypt':
                    default_name = f"{item.stem}.encrypted"
                    custom_name = input(f"Enter name for encrypted file (press Enter to use '{default_name}'): ").strip()
                    output_file = output_path / (custom_name if custom_name else default_name)
                    if output_file.exists():
                        overwrite = input(f"File {output_file} already exists. Overwrite? (y/n): ").lower()
                        if overwrite != 'y':
                            log_message("Skipping file...", log_file)
                            continue
                    log_message(f"Encrypting: {item} -> {output_file}", log_file)
                    encrypt_file(str(item), str(output_file), key, iv, log_file)
                    log_message(f"Successfully encrypted: {item}", log_file)
                    success_count += 1
                else:  # decrypt
                    log_message(f"Decrypting: {item}", log_file)
                    success = decrypt_file(str(item), str(output_path), key, iv, log_file)
                    if success:
                        log_message(f"Successfully decrypted: {item}", log_file)
                        success_count += 1
            except Exception as e:
                log_message(f"Error processing file {item}: {str(e)}", log_file)
                continue
        elif item.is_dir():
            log_message(f"\nProcessing directory: {item}", log_file)
            default_dir_name = item.name
            custom_dir_name = input(f"Enter custom name for output directory (press Enter to use '{default_dir_name}'): ").strip()
            new_output_dir = output_path / (custom_dir_name if custom_dir_name else default_dir_name)
            process_directory(str(item), str(new_output_dir), key, iv, mode, log_file)
    if success_count > 0:
        log_message(f"Directory processed successfully: {output_dir}", log_file)
    else:
        log_message(f"Directory processed with errors: не удалось обработать ни одного файла в {output_dir}", log_file)

def get_memory_usage():
    """Get current memory usage in MB"""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024  # Convert to MB

def get_log_filename():
    """Generate log filename with timestamp"""
    timestamp = datetime.datetime.now().strftime("%d.%m.%Y-%H-%M-%S")
    return f"crypto_log{timestamp}.log"

def log_message(msg: str, log_file: str):
    """Log message with timestamp and memory usage"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    memory_usage = get_memory_usage()
    log_entry = f"[{timestamp}] [Memory: {memory_usage:.2f} MB] {msg}"
    print(log_entry)
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(log_entry + '\n')

def main():
    # Создаем имя лог-файла при старте программы
    log_file = get_log_filename()
    log_message(f"Starting crypto utility session. Log file: {log_file}", log_file)
    
    parser = argparse.ArgumentParser(description='File encryption/decryption utility')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Operation mode')
    parser.add_argument('input_path', help='Input file or directory path')
    parser.add_argument('output_path', help='Output file or directory path')
    parser.add_argument('--key-file', help='Path to key file (for decryption)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_path):
        log_message(f"Error: Input path '{args.input_path}' does not exist", log_file)
        sys.exit(1)
    
    # Генерируем или загружаем ключ
    if args.mode == 'encrypt':
        log_message("Генерация ключа шифрования...", log_file)
        key, iv = generate_key_from_mouse()
        log_message("Ключ сгенерирован успешно!", log_file)
        # Сохраняем ключ
        key_file = os.path.join(os.path.dirname(args.output_path), 'encryption_key.json')
        save_key(key, iv, key_file)
        log_message(f"Ключ сохранен в файл: {key_file}", log_file)
    else:
        if not args.key_file:
            log_message("Error: Key file is required for decryption", log_file)
            sys.exit(1)
        log_message("Загрузка ключа...", log_file)
        try:
            key, iv = load_key(args.key_file)
        except ValueError as ve:
            log_message(str(ve), log_file)
            sys.exit(1)
        log_message("Ключ загружен успешно!", log_file)
    
    if os.path.isdir(args.input_path):
        process_directory(args.input_path, args.output_path, key, iv, args.mode, log_file)
    else:
        if args.mode == 'encrypt':
            encrypt_file(args.input_path, args.output_path, key, iv, log_file)
            log_message(f"File encrypted successfully: {args.output_path}", log_file)
        else:
            success = decrypt_file(args.input_path, args.output_path, key, iv, log_file)
            if success:
                log_message(f"File decrypted successfully: {args.output_path}", log_file)

if __name__ == '__main__':
    main() 