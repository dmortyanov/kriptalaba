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
from pathlib import Path

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key from password and salt"""
    # Используем PBKDF2-подобный подход для генерации ключа
    result = password.encode('utf-8')
    for _ in range(1000):
        result = hashlib.sha256(salt + result).digest()
    return result

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Simple XOR encryption/decryption"""
    result = bytearray()
    key_length = len(key)
    for i in range(len(data)):
        result.append(data[i] ^ key[i % key_length])
    return bytes(result)

def encrypt_metadata(metadata: dict, key: bytes) -> bytes:
    """Encrypt file metadata"""
    # Преобразуем метаданные в JSON и затем в bytes
    metadata_bytes = json.dumps(metadata).encode('utf-8')
    # Шифруем метаданные
    encrypted_metadata = xor_bytes(metadata_bytes, key)
    # Добавляем длину метаданных в начало (4 байта)
    length_bytes = len(encrypted_metadata).to_bytes(4, byteorder='big')
    return length_bytes + encrypted_metadata

def decrypt_metadata(encrypted_data: bytes, key: bytes) -> tuple[dict, int]:
    """Decrypt file metadata and return metadata dict and bytes read"""
    # Читаем длину метаданных (первые 4 байта)
    metadata_length = int.from_bytes(encrypted_data[:4], byteorder='big')
    # Извлекаем и расшифровываем метаданные
    encrypted_metadata = encrypted_data[4:4+metadata_length]
    decrypted_metadata = xor_bytes(encrypted_metadata, key)
    # Преобразуем JSON обратно в словарь
    metadata = json.loads(decrypted_metadata.decode('utf-8'))
    return metadata, 4 + metadata_length

def encrypt_file(input_file: str, output_file: str, password: str) -> None:
    """Encrypt a file using XOR cipher with metadata encryption"""
    try:
        # Генерируем соль
        salt = os.urandom(16)
        key = generate_key(password, salt)
        
        # Собираем метаданные файла
        input_path = Path(input_file)
        metadata = {
            'original_name': input_path.name,
            'size': input_path.stat().st_size,
            'extension': input_path.suffix,
            'created_time': input_path.stat().st_ctime,
            'modified_time': input_path.stat().st_mtime,
            'encryption_time': time.time()
        }
        
        # Шифруем метаданные
        encrypted_metadata = encrypt_metadata(metadata, key)
        
        # Читаем и шифруем данные файла
        with open(input_file, 'rb') as file:
            data = file.read()
        encrypted_data = xor_bytes(data, key)
        
        # Записываем всё в выходной файл:
        # [соль(16 байт)][зашифрованные метаданные][зашифрованные данные]
        with open(output_file, 'wb') as file:
            file.write(salt + encrypted_metadata + encrypted_data)
            
    except Exception as e:
        print(f"Error encrypting file {input_file}: {str(e)}")
        raise

def decrypt_file(input_file: str, output_file: str, password: str) -> dict:
    """Decrypt a file using XOR cipher and return metadata"""
    try:
        with open(input_file, 'rb') as file:
            data = file.read()
        
        if len(data) < 16:
            raise ValueError("File is too small to be a valid encrypted file")
        
        # Извлекаем соль (первые 16 байт)
        salt = data[:16]
        key = generate_key(password, salt)
        
        # Расшифровываем метаданные
        metadata, metadata_length = decrypt_metadata(data[16:], key)
        
        # Расшифровываем данные файла
        encrypted_data = data[16 + metadata_length:]
        decrypted_data = xor_bytes(encrypted_data, key)
        
        # Если выходной файл не указан, используем оригинальное имя
        if not output_file:
            output_dir = Path(input_file).parent
            output_file = str(output_dir / metadata['original_name'])
        
        # Записываем расшифрованные данные
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        
        # Восстанавливаем временные метки файла
        os.utime(output_file, (metadata['created_time'], metadata['modified_time']))
        
        return metadata
            
    except Exception as e:
        print(f"Error decrypting file {input_file}: {str(e)}")
        raise

def process_directory(input_dir: str, output_dir: str, password: str, mode: str) -> None:
    """Process all files in a directory recursively"""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Создаем выходную директорию, если она не существует
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Обрабатываем все файлы и поддиректории
    for item in input_path.iterdir():
        if item.is_file():
            try:
                print(f"\nProcessing file: {item}")
                
                if mode == 'encrypt':
                    # При шифровании спрашиваем только имя зашифрованного файла
                    default_name = f"{item.stem}.encrypted"
                    custom_name = input(f"Enter name for encrypted file (press Enter to use '{default_name}'): ").strip()
                    output_file = output_path / (custom_name if custom_name else default_name)
                    
                    if output_file.exists():
                        overwrite = input(f"File {output_file} already exists. Overwrite? (y/n): ").lower()
                        if overwrite != 'y':
                            print("Skipping file...")
                            continue
                    
                    print(f"Encrypting: {item} -> {output_file}")
                    encrypt_file(str(item), str(output_file), password)
                    print(f"Successfully encrypted: {item}")
                    
                else:  # decrypt
                    # При расшифровке используем оригинальное имя из метаданных
                    output_file = output_path / "temp_name"  # Временное имя
                    print(f"Decrypting: {item}")
                    metadata = decrypt_file(str(item), str(output_file), password)
                    
                    # Перемещаем файл, используя оригинальное имя
                    final_output = output_path / metadata['original_name']
                    if final_output.exists():
                        overwrite = input(f"File {final_output} already exists. Overwrite? (y/n): ").lower()
                        if overwrite != 'y':
                            os.remove(str(output_file))  # Удаляем временный файл
                            print("Skipping file...")
                            continue
                    
                    os.replace(str(output_file), str(final_output))
                    print(f"Successfully decrypted: {item} -> {final_output}")
                    print("Original metadata:")
                    for key, value in metadata.items():
                        print(f"  {key}: {value}")
                    
            except Exception as e:
                print(f"Error processing file {item}: {str(e)}")
                continue
        
        elif item.is_dir():
            # Для директорий спрашиваем новое имя
            print(f"\nProcessing directory: {item}")
            default_dir_name = item.name
            custom_dir_name = input(f"Enter custom name for output directory (press Enter to use '{default_dir_name}'): ").strip()
            
            new_output_dir = output_path / (custom_dir_name if custom_dir_name else default_dir_name)
            process_directory(str(item), str(new_output_dir), password, mode)

def main():
    parser = argparse.ArgumentParser(description='File encryption/decryption utility')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Operation mode')
    parser.add_argument('input_path', help='Input file or directory path')
    parser.add_argument('output_path', help='Output file or directory path')
    parser.add_argument('--password', required=True, help='Password for encryption/decryption')
    parser.add_argument('--batch', action='store_true', help='Batch mode (use default names without asking)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_path):
        print(f"Error: Input path '{args.input_path}' does not exist")
        sys.exit(1)
    
    if os.path.isdir(args.input_path):
        process_directory(args.input_path, args.output_path, args.password, args.mode)
        print(f"Directory processed successfully: {args.output_path}")
    else:
        if args.mode == 'encrypt':
            encrypt_file(args.input_path, args.output_path, args.password)
            print(f"File encrypted successfully: {args.output_path}")
        else:
            metadata = decrypt_file(args.input_path, args.output_path, args.password)
            print(f"File decrypted successfully: {args.output_path}")
            print("Original metadata:")
            for key, value in metadata.items():
                print(f"  {key}: {value}")

if __name__ == '__main__':
    main() 