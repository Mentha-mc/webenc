#!/usr/bin/env python3
"""
Minecraft 包加密/解密后端 API
基于C#原版McCrypt逻辑的加密解密功能
"""

import os
import sys
import json
import uuid
import base64
import struct
import hashlib
import shutil
import random
import string
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import tempfile
import zipfile

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# 尝试导入加密库
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("错误: pycryptodome 未安装，请运行: pip install pycryptodome")
    sys.exit(1)

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 配置
UPLOAD_FOLDER = 'temp_uploads'
OUTPUT_FOLDER = 'temp_outputs'
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
ALLOWED_EXTENSIONS = {'zip', 'mcpack', 'mcworld', 'mctemplate'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 确保目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


class AESCFBCrypto:
    """AES CFB模式加密解密工具类"""
    
    @staticmethod
    def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        """AES CFB模式加密"""
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=8)
        return cipher.encrypt(data)
    
    @staticmethod
    def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        """AES CFB模式解密"""
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=8)
        return cipher.decrypt(data)


class KeysManager:
    """密钥管理器"""
    
    def __init__(self, db_path: str = "keys.db"):
        self.db_path = db_path
        self.keys_cache = {}
        self.default_skin_key = b"s5s5ejuDru4uchuF2drUFuthaspAbepE"
        self._init_database()
        self._load_keys()
    
    def _init_database(self):
        """初始化密钥数据库"""
        if not os.path.exists(self.db_path):
            self._create_database()
    
    def _create_database(self):
        """创建新的密钥数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                uuid TEXT PRIMARY KEY,
                content_key TEXT NOT NULL,
                created_date TEXT NOT NULL,
                description TEXT
            )
        ''')
        
        # 添加默认皮肤密钥
        cursor.execute('''
            INSERT OR REPLACE INTO keys (uuid, content_key, created_date, description)
            VALUES (?, ?, ?, ?)
        ''', ("default_skin", self.default_skin_key.decode('utf-8'), 
              datetime.now().isoformat(), "默认皮肤包密钥"))
        
        conn.commit()
        conn.close()
        
        self.keys_cache["default_skin"] = self.default_skin_key.decode('utf-8')
    
    def _load_keys(self):
        """从数据库加载密钥"""
        if not os.path.exists(self.db_path):
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT uuid, content_key FROM keys")
        for row in cursor.fetchall():
            self.keys_cache[row[0]] = row[1]
        
        conn.close()
    
    def lookup_key(self, pack_uuid: str) -> bytes:
        """查找UUID对应的加密密钥"""
        if pack_uuid in self.keys_cache:
            return self.keys_cache[pack_uuid].encode('utf-8')
        return self.default_skin_key
    
    def add_key(self, pack_uuid: str, content_key: str, description: str = ""):
        """添加新密钥到数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO keys (uuid, content_key, created_date, description)
            VALUES (?, ?, ?, ?)
        ''', (pack_uuid, content_key, datetime.now().isoformat(), description))
        
        conn.commit()
        conn.close()
        
        self.keys_cache[pack_uuid] = content_key
    
    @staticmethod
    def generate_key() -> str:
        """生成随机密钥"""
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        return ''.join(random.choice(allowed_chars) for _ in range(32))


class ManifestManager:
    """清单管理器"""
    
    @staticmethod
    def read_uuid(manifest_path: str) -> str:
        """从manifest.json读取UUID"""
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
                
            header = manifest.get('header', {})
            pack_uuid = header.get('uuid', '')
            
            if not pack_uuid:
                pack_uuid = str(uuid.uuid4())
                header['uuid'] = pack_uuid
                
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    json.dump(manifest, f, indent=2)
            
            return pack_uuid
            
        except Exception:
            return str(uuid.uuid4())
    
    @staticmethod
    def sign_manifest(pack_path: str):
        """签名manifest.json"""
        manifest_path = os.path.join(pack_path, "manifest.json")
        
        try:
            with open(manifest_path, 'rb') as f:
                manifest_data = f.read()
            
            signature_data = [{
                "path": "manifest.json",
                "hash": base64.b64encode(hashlib.sha256(manifest_data).digest()).decode('utf-8')
            }]
            
            signatures_path = os.path.join(pack_path, "signatures.json")
            with open(signatures_path, 'w', encoding='utf-8') as f:
                json.dump(signature_data, f, indent=2)
                
        except Exception as e:
            raise Exception(f"签名清单时出错：{e}")


class MarketplaceEncryptor:
    """市场包加密器"""
    
    DONT_ENCRYPT = ["manifest.json", "contents.json", "texts", "pack_icon.png", "ui"]
    
    def __init__(self, pack_path: str, pack_uuid: str, content_key: str):
        self.pack_path = Path(pack_path)
        self.pack_uuid = pack_uuid
        self.content_key = content_key
    
    def _should_encrypt(self, rel_path: str) -> bool:
        """检查文件是否应该被加密"""
        path_parts = rel_path.replace('\\', '/').split('/')
        for part in path_parts:
            if part in self.DONT_ENCRYPT:
                return False
        return True
    
    def _create_encrypted_header(self, data: bytes) -> bytes:
        """创建加密文件头部"""
        header = bytearray(0x100)  # 256字节头部
        
        struct.pack_into('<I', header, 0x00, 0)  # 版本
        struct.pack_into('<I', header, 0x04, 0x9BCFB9FC)  # 魔数
        struct.pack_into('<Q', header, 0x08, 0)  # 未知
        
        uuid_bytes = self.pack_uuid.encode('utf-8')
        header[0x10] = len(uuid_bytes)
        header[0x11:0x11 + len(uuid_bytes)] = uuid_bytes
        
        return bytes(header) + data
    
    def _encrypt_file_content(self, file_path: Path, file_key: str) -> bytes:
        """加密文件内容"""
        with open(file_path, 'rb') as f:
            content = f.read()
        
        key_bytes = file_key.encode('utf-8')
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b'\x00')
        else:
            key_bytes = key_bytes[:32]
        
        iv = key_bytes[:16]
        encrypted_content = AESCFBCrypto.encrypt(key_bytes, iv, content)
        return encrypted_content
    
    def _create_contents_json(self, encrypted_files: List[tuple], directories: List[str]) -> str:
        """创建contents.json文件"""
        content_entries = []
        
        for file_path, file_key in encrypted_files:
            rel_path = str(Path(file_path).relative_to(self.pack_path)).replace('\\', '/')
            content_entries.append({
                "path": rel_path,
                "key": file_key
            })
        
        for dir_path in directories:
            rel_path = str(Path(dir_path).relative_to(self.pack_path)).replace('\\', '/') + '/'
            content_entries.append({
                "path": rel_path
            })
        
        contents = {
            "version": 1,
            "content": content_entries
        }
        
        return json.dumps(contents, indent=2)
    
    def encrypt_contents(self) -> dict:
        """加密包内容"""
        try:
            all_files = []
            all_directories = []
            
            for root, dirs, files in os.walk(self.pack_path):
                for dir_name in dirs:
                    dir_path = Path(root) / dir_name
                    all_directories.append(dir_path)
                
                for file_name in files:
                    file_path = Path(root) / file_name
                    all_files.append(file_path)
            
            total_files = len(all_files)
            encrypted_files = []
            processed = 0
            
            for file_path in all_files:
                try:
                    rel_path = str(file_path.relative_to(self.pack_path)).replace('\\', '/')
                    
                    if self._should_encrypt(rel_path):
                        file_key = KeysManager.generate_key()
                        encrypted_content = self._encrypt_file_content(file_path, file_key)
                        
                        with open(file_path, 'wb') as f:
                            f.write(encrypted_content)
                        
                        encrypted_files.append((str(file_path), file_key))
                    
                    processed += 1
                    
                except Exception as e:
                    print(f"加密文件 {file_path} 时出错：{e}")
            
            if encrypted_files:
                contents_json = self._create_contents_json(encrypted_files, all_directories)
                
                content_key_bytes = self.content_key.encode('utf-8')
                if len(content_key_bytes) < 32:
                    content_key_bytes = content_key_bytes.ljust(32, b'\x00')
                else:
                    content_key_bytes = content_key_bytes[:32]
                
                iv = content_key_bytes[:16]
                encrypted_json = AESCFBCrypto.encrypt(content_key_bytes, iv, contents_json.encode('utf-8'))
                
                encrypted_contents_with_header = self._create_encrypted_header(encrypted_json)
                
                contents_path = self.pack_path / "contents.json"
                with open(contents_path, 'wb') as f:
                    f.write(encrypted_contents_with_header)
            
            return {
                'success': True,
                'encrypted_files': len(encrypted_files),
                'total_files': total_files,
                'uuid': self.pack_uuid,
                'content_key': self.content_key
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class MarketplaceDecryptor:
    """市场包解密器"""
    
    def __init__(self, pack_path: str, content_key: str = None):
        self.pack_path = Path(pack_path)
        self.content_key = content_key or "s5s5ejuDru4uchuF2drUFuthaspAbepE"
        self.keys_manager = KeysManager()
    
    def _is_content_file_encrypted(self, file_path: Path) -> bool:
        """检查文件是否加密"""
        try:
            with open(file_path, 'rb') as f:
                if f.read(4):  # 读取前4字节
                    f.seek(0x4)
                    magic = struct.unpack('<I', f.read(4))[0]
                    return magic == 0x9BCFB9FC
        except:
            pass
        return False
    
    def _decrypt_content_file(self, file_path: Path) -> bytes:
        """解密内容文件"""
        with open(file_path, 'rb') as f:
            contents = f.read()
        
        if len(contents) < 0x100:
            return contents
        
        # 检查魔数
        magic = struct.unpack('<I', contents[0x4:0x8])[0]
        if magic != 0x9BCFB9FC:
            return contents
        
        # 获取UUID
        uuid_size = contents[0x10]
        uuid_bytes = contents[0x11:0x11 + uuid_size]
        pack_uuid = uuid_bytes.decode('utf-8')
        
        # 获取密钥
        key = self.keys_manager.lookup_key(pack_uuid)
        
        # 解密
        cipher_text = contents[0x100:]
        return self._decrypt_aes(key, cipher_text)
    
    def _decrypt_file(self, file_path: Path, file_key: str) -> bytes:
        """解密普通文件"""
        with open(file_path, 'rb') as f:
            contents = f.read()
        
        key_bytes = file_key.encode('utf-8')
        return self._decrypt_aes(key_bytes, contents)
    
    def _decrypt_aes(self, key: bytes, data: bytes) -> bytes:
        """AES解密"""
        if len(key) < 32:
            key = key.ljust(32, b'\x00')
        else:
            key = key[:32]
        
        iv = key[:16]
        return AESCFBCrypto.decrypt(key, iv, data)
    
    def _crack_skin_pack(self, pack_path: Path):
        """破解皮肤包"""
        skins_json_path = pack_path / "skins.json"
        if not skins_json_path.exists():
            return
        
        try:
            with open(skins_json_path, 'r', encoding='utf-8') as f:
                skins_data = json.load(f)
            
            # 将所有皮肤设为免费
            if 'skins' in skins_data:
                for skin in skins_data['skins']:
                    skin['type'] = 'free'
            
            with open(skins_json_path, 'w', encoding='utf-8') as f:
                json.dump(skins_data, f, indent=2)
                
        except Exception as e:
            print(f"破解皮肤包失败: {e}")
    
    def _crack_world(self, pack_path: Path):
        """破解世界包"""
        level_dat_path = pack_path / "level.dat"
        if not level_dat_path.exists():
            return
        
        try:
            with open(level_dat_path, 'rb') as f:
                level_dat = bytearray(f.read())
            
            # 替换所有"prid"为"ared"
            while True:
                offset = level_dat.find(b"prid")
                if offset == -1:
                    break
                level_dat[offset:offset+4] = b"ared"
            
            with open(level_dat_path, 'wb') as f:
                f.write(level_dat)
                
        except Exception as e:
            print(f"破解世界包失败: {e}")
    
    def decrypt_contents(self) -> dict:
        """解密包内容"""
        try:
            total_files = 0
            decrypted_files = 0
            
            # 统计总文件数
            for root, dirs, files in os.walk(self.pack_path):
                total_files += len(files)
            
            # 查找并解密contents.json
            contents_json_path = self.pack_path / "contents.json"
            contents_data = None
            
            if contents_json_path.exists() and self._is_content_file_encrypted(contents_json_path):
                decrypted_content = self._decrypt_content_file(contents_json_path)
                
                # 写回解密后的contents.json
                with open(contents_json_path, 'wb') as f:
                    f.write(decrypted_content)
                
                try:
                    contents_data = json.loads(decrypted_content.decode('utf-8'))
                    decrypted_files += 1
                except:
                    pass
            
            # 如果有contents.json，按其内容解密文件
            if contents_data and 'content' in contents_data:
                for entry in contents_data['content']:
                    if 'key' not in entry:
                        continue
                    
                    file_path = self.pack_path / entry['path']
                    if file_path.exists() and file_path.is_file():
                        try:
                            decrypted_content = self._decrypt_file(file_path, entry['key'])
                            with open(file_path, 'wb') as f:
                                f.write(decrypted_content)
                            decrypted_files += 1
                        except Exception as e:
                            print(f"解密文件 {file_path} 失败: {e}")
            
            # 处理db文件夹
            db_path = self.pack_path / "db"
            if db_path.exists():
                for file_path in db_path.rglob("*"):
                    if file_path.is_file() and self._is_content_file_encrypted(file_path):
                        try:
                            decrypted_content = self._decrypt_content_file(file_path)
                            with open(file_path, 'wb') as f:
                                f.write(decrypted_content)
                            decrypted_files += 1
                        except Exception as e:
                            print(f"解密db文件 {file_path} 失败: {e}")
            
            # 破解特殊内容
            self._crack_skin_pack(self.pack_path)
            self._crack_world(self.pack_path)
            
            return {
                'success': True,
                'decrypted_files': decrypted_files,
                'total_files': total_files
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class PackEncryptor:
    """包加密器主类"""
    
    def __init__(self, pack_path: str):
        self.pack_path = Path(pack_path)
        self.keys_manager = KeysManager()
    
    def encrypt_pack(self, custom_key: str = None) -> dict:
        """加密包"""
        try:
            manifest_path = self.pack_path / "manifest.json"
            if not manifest_path.exists():
                return {
                    'success': False,
                    'error': '在包目录中未找到manifest.json'
                }
            
            pack_uuid = ManifestManager.read_uuid(str(manifest_path))
            
            if custom_key:
                content_key = custom_key
                self.keys_manager.add_key(pack_uuid, content_key, "用户自定义密钥")
            else:
                content_key_bytes = self.keys_manager.lookup_key(pack_uuid)
                content_key = content_key_bytes.decode('utf-8')
            
            ManifestManager.sign_manifest(str(self.pack_path))
            
            marketplace_encryptor = MarketplaceEncryptor(
                str(self.pack_path), pack_uuid, content_key
            )
            
            result = marketplace_encryptor.encrypt_contents()
            
            if result['success']:
                result['pack_info'] = self._get_pack_info()
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_pack_info(self) -> dict:
        """获取包信息"""
        manifest_path = self.pack_path / "manifest.json"
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            header = manifest.get('header', {})
            return {
                'name': header.get('name', self.pack_path.name),
                'description': header.get('description', ''),
                'version': '.'.join(map(str, header.get('version', [0, 0, 0]))),
                'uuid': header.get('uuid', ''),
                'pack_scope': header.get('pack_scope', ''),
                'min_engine_version': header.get('min_engine_version', [])
            }
            
        except Exception:
            return {
                'name': self.pack_path.name,
                'description': '',
                'version': '0.0.0',
                'uuid': '',
                'pack_scope': '',
                'min_engine_version': []
            }


class PackDecryptor:
    """包解密器主类"""
    
    def __init__(self, pack_path: str):
        self.pack_path = Path(pack_path)
    
    def decrypt_pack(self, custom_key: str = None) -> dict:
        """解密包"""
        try:
            marketplace_decryptor = MarketplaceDecryptor(
                str(self.pack_path), custom_key
            )
            
            result = marketplace_decryptor.decrypt_contents()
            
            if result['success']:
                result['pack_info'] = self._get_pack_info()
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_pack_info(self) -> dict:
        """获取包信息"""
        manifest_path = self.pack_path / "manifest.json"
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            header = manifest.get('header', {})
            return {
                'name': header.get('name', self.pack_path.name),
                'description': header.get('description', ''),
                'version': '.'.join(map(str, header.get('version', [0, 0, 0]))),
                'uuid': header.get('uuid', ''),
                'pack_scope': header.get('pack_scope', ''),
                'min_engine_version': header.get('min_engine_version', [])
            }
            
        except Exception:
            return {
                'name': self.pack_path.name,
                'description': '',
                'version': '0.0.0',
                'uuid': '',
                'pack_scope': '',
                'min_engine_version': []
            }


def allowed_file(filename):
    """检查文件类型是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def find_manifest_directory(base_path):
    """递归查找包含manifest.json的目录"""
    print(f"开始在 {base_path} 中查找manifest.json...")
    
    # 首先检查根目录
    manifest_path = os.path.join(base_path, "manifest.json")
    if os.path.exists(manifest_path):
        print(f"在根目录找到manifest.json: {manifest_path}")
        return base_path
    
    # 递归检查子目录
    for root, dirs, files in os.walk(base_path):
        if 'manifest.json' in files:
            print(f"在子目录找到manifest.json: {root}")
            return root
    
    print(f"在 {base_path} 中未找到manifest.json")
    return None


@app.route('/api/debug-upload', methods=['POST'])
def debug_upload():
    """调试文件上传（仅用于开发）"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': '没有文件'}), 400
        
        files = request.files.getlist('files')
        debug_info = {
            'file_count': len(files),
            'files': []
        }
        
        for file in files:
            debug_info['files'].append({
                'filename': file.filename,
                'size': len(file.read()),
                'content_type': file.content_type
            })
            file.seek(0)  # 重置文件指针
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'ok',
        'crypto_available': CRYPTO_AVAILABLE,
        'version': '1.0.0'
    })


@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """生成随机密钥"""
    try:
        key = KeysManager.generate_key()
        return jsonify({
            'success': True,
            'key': key
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/encrypt', methods=['POST'])
def encrypt_pack():
    """加密包文件夹"""
    try:
        custom_key = request.form.get('custom_key', '').strip()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 检查是否有文件上传（支持多文件上传表示文件夹）
        if 'files' not in request.files:
            return jsonify({
                'success': False,
                'error': '没有上传文件'
            }), 400
        
        files = request.files.getlist('files')
        if not files or len(files) == 0:
            return jsonify({
                'success': False,
                'error': '没有选择文件'
            }), 400
        
        # 创建临时目录来重建文件夹结构
        pack_root = os.path.join(app.config['UPLOAD_FOLDER'], f"pack_{timestamp}")
        os.makedirs(pack_root, exist_ok=True)
        
        print(f"创建临时目录: {pack_root}")
        
        # 重建文件夹结构
        manifest_found = False
        folder_name = None
        
        for file in files:
            if file.filename == '':
                continue
                
            # 获取相对路径（浏览器会提供完整的相对路径）
            file_path = file.filename
            if file_path.startswith('/'):
                file_path = file_path[1:]
            
            # 获取文件夹名称（第一级目录）
            if folder_name is None and '/' in file_path:
                folder_name = file_path.split('/')[0]
            
            # 检查是否是manifest.json
            if file_path.endswith('manifest.json'):
                manifest_found = True
                print(f"上传时发现manifest.json: {file_path}")
            
            # 创建完整的文件路径
            full_path = os.path.join(pack_root, file_path)
            
            # 确保目录存在
            dir_path = os.path.dirname(full_path)
            if dir_path and dir_path != pack_root:
                os.makedirs(dir_path, exist_ok=True)
            
            # 保存文件
            try:
                file.save(full_path)
                print(f"保存文件: {full_path}")
            except Exception as e:
                print(f"保存文件失败 {file_path}: {e}")
        
        # 查找包含manifest.json的目录
        pack_directory = find_manifest_directory(pack_root)
        
        if not pack_directory:
            # 列出所有上传的文件进行调试
            print("上传的文件列表:")
            for root, dirs, files_in_dir in os.walk(pack_root):
                for file in files_in_dir:
                    rel_path = os.path.relpath(os.path.join(root, file), pack_root)
                    print(f"  {rel_path}")
            
            return jsonify({
                'success': False,
                'error': '在上传的文件中未找到manifest.json。请确保选择了正确的包文件夹。'
            }), 400
        
        print(f"使用包目录: {pack_directory}")
        
        # 加密包
        encryptor = PackEncryptor(pack_directory)
        result = encryptor.encrypt_pack(custom_key if custom_key else None)
        
        if not result['success']:
            return jsonify(result), 400
        
        # 创建加密后的ZIP文件
        pack_name = result.get('pack_info', {}).get('name', 'minecraft_pack')
        # 清理包名称中的特殊字符
        pack_name = "".join(c for c in pack_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        if not pack_name:
            pack_name = 'minecraft_pack'
        
        output_filename = f"encrypted_{pack_name}_{timestamp}.zip"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        shutil.make_archive(output_path.replace('.zip', ''), 'zip', pack_directory)
        
        # 清理临时文件
        try:
            shutil.rmtree(pack_root)
        except Exception as e:
            print(f"清理临时文件失败: {e}")
        
        result['download_filename'] = output_filename
        return jsonify(result)
        
    except Exception as e:
        print(f"加密过程中出错: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/decrypt', methods=['POST'])
def decrypt_pack():
    """解密包文件夹"""
    try:
        custom_key = request.form.get('custom_key', '').strip()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 检查是否有文件上传
        if 'files' not in request.files:
            return jsonify({
                'success': False,
                'error': '没有上传文件'
            }), 400
        
        files = request.files.getlist('files')
        if not files or len(files) == 0:
            return jsonify({
                'success': False,
                'error': '没有选择文件'
            }), 400
        
        # 创建临时目录来重建文件夹结构
        pack_root = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypt_{timestamp}")
        os.makedirs(pack_root, exist_ok=True)
        
        print(f"创建解密临时目录: {pack_root}")
        
        # 重建文件夹结构
        for file in files:
            if file.filename == '':
                continue
                
            # 获取相对路径
            file_path = file.filename
            if file_path.startswith('/'):
                file_path = file_path[1:]
            
            # 创建完整的文件路径
            full_path = os.path.join(pack_root, file_path)
            
            # 确保目录存在
            dir_path = os.path.dirname(full_path)
            if dir_path and dir_path != pack_root:
                os.makedirs(dir_path, exist_ok=True)
            
            # 保存文件
            try:
                file.save(full_path)
                print(f"保存文件: {full_path}")
            except Exception as e:
                print(f"保存文件失败 {file_path}: {e}")
        
        # 查找包根目录
        pack_directory = find_manifest_directory(pack_root)
        if not pack_directory:
            # 如果没找到manifest.json，就使用根目录（可能是加密的包）
            pack_directory = pack_root
        
        print(f"使用解密目录: {pack_directory}")
        
        # 解密包
        decryptor = PackDecryptor(pack_directory)
        result = decryptor.decrypt_pack(custom_key if custom_key else None)
        
        if not result['success']:
            return jsonify(result), 400
        
        # 创建解密后的ZIP文件
        pack_name = result.get('pack_info', {}).get('name', 'minecraft_pack')
        # 清理包名称中的特殊字符
        pack_name = "".join(c for c in pack_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        if not pack_name:
            pack_name = 'minecraft_pack'
        
        output_filename = f"decrypted_{pack_name}_{timestamp}.zip"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        shutil.make_archive(output_path.replace('.zip', ''), 'zip', pack_directory)
        
        # 清理临时文件
        try:
            shutil.rmtree(pack_root)
        except Exception as e:
            print(f"清理临时文件失败: {e}")
        
        result['download_filename'] = output_filename
        return jsonify(result)
        
    except Exception as e:
        print(f"解密过程中出错: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/encrypt-zip', methods=['POST'])
def encrypt_zip_pack():
    """加密ZIP格式的包文件（备用方法）"""
    try:
        # 检查文件是否存在
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': '没有上传文件'
            }), 400
        
        file = request.files['file']
        custom_key = request.form.get('custom_key', '').strip()
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': '没有选择文件'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': f'不支持的文件类型。支持的类型: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400
        
        # 保存上传的文件
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # 解压文件
        extract_path = os.path.join(app.config['UPLOAD_FOLDER'], f"extracted_{timestamp}")
        os.makedirs(extract_path, exist_ok=True)
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
        except zipfile.BadZipFile:
            return jsonify({
                'success': False,
                'error': '无效的ZIP文件'
            }), 400
        
        # 查找包根目录（包含manifest.json的目录）
        pack_root = find_manifest_directory(extract_path)
        
        if not pack_root:
            return jsonify({
                'success': False,
                'error': '在上传的文件中未找到manifest.json'
            }), 400
        
        # 加密包
        encryptor = PackEncryptor(pack_root)
        result = encryptor.encrypt_pack(custom_key if custom_key else None)
        
        if not result['success']:
            return jsonify(result), 400
        
        # 创建加密后的ZIP文件
        output_filename = f"encrypted_{timestamp}_{filename}"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        shutil.make_archive(output_path.replace('.zip', ''), 'zip', pack_root)
        
        # 清理临时文件
        try:
            os.remove(file_path)
            shutil.rmtree(extract_path)
        except Exception:
            pass
        
        result['download_filename'] = output_filename
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/decrypt-zip', methods=['POST'])
def decrypt_zip_pack():
    """解密ZIP格式的包文件（备用方法）"""
    try:
        # 检查文件是否存在
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': '没有上传文件'
            }), 400
        
        file = request.files['file']
        custom_key = request.form.get('custom_key', '').strip()
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': '没有选择文件'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': f'不支持的文件类型。支持的类型: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400
        
        # 保存上传的文件
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # 解压文件
        extract_path = os.path.join(app.config['UPLOAD_FOLDER'], f"extracted_decrypt_{timestamp}")
        os.makedirs(extract_path, exist_ok=True)
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
        except zipfile.BadZipFile:
            return jsonify({
                'success': False,
                'error': '无效的ZIP文件'
            }), 400
        
        # 查找包根目录
        pack_root = find_manifest_directory(extract_path)
        if not pack_root:
            # 如果没找到manifest.json，就使用根目录（可能是加密的包）
            pack_root = extract_path
        
        # 解密包
        decryptor = PackDecryptor(pack_root)
        result = decryptor.decrypt_pack(custom_key if custom_key else None)
        
        if not result['success']:
            return jsonify(result), 400
        
        # 创建解密后的ZIP文件
        output_filename = f"decrypted_{timestamp}_{filename}"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        shutil.make_archive(output_path.replace('.zip', ''), 'zip', pack_root)
        
        # 清理临时文件
        try:
            os.remove(file_path)
            shutil.rmtree(extract_path)
        except Exception:
            pass
        
        result['download_filename'] = output_filename
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """下载加密后的文件"""
    try:
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
        
        if not os.path.exists(file_path):
            return jsonify({
                'success': False,
                'error': '文件不存在'
            }), 404
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/cleanup', methods=['POST'])
def cleanup_files():
    """清理临时文件"""
    try:
        # 清理超过1小时的文件
        import time
        current_time = time.time()
        
        for folder in [app.config['UPLOAD_FOLDER'], app.config['OUTPUT_FOLDER']]:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path):
                    file_age = current_time - os.path.getctime(file_path)
                    if file_age > 3600:  # 1小时
                        os.remove(file_path)
        
        return jsonify({
            'success': True,
            'message': '临时文件清理完成'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)