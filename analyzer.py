#!/usr/bin/env python3

import sys
import os
import hashlib
import re
import math
import datetime
import json
import struct
import argparse
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional, Any
import time
from collections import defaultdict

# Security imports with fallbacks
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("[!] Installing pefile...")
    os.system(f"{sys.executable} -m pip install pefile")
    import pefile
    PEFILE_AVAILABLE = True

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("[!] Capstone not available - disassembly disabled")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[!] YARA not available - rule scanning disabled")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("[!] python-magic not available - MIME detection disabled")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MalwareAnalyzerPro:
    """Advanced malware analyzer with comprehensive analysis capabilities"""
    
    def __init__(self, filepath: str, config: Dict[str, Any] = None):
        """Initialize the analyzer with file path and configuration"""
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Load configuration
        self.config = config or {}
        self.verbose = self.config.get('verbose', False)
        self.quick_mode = self.config.get('quick_mode', False)
        
        # Read file data
        with open(filepath, 'rb') as f:
            self.data = f.read()
        
        self.filename = self.filepath.name
        self.filesize = len(self.data)
        self.pe = None
        self.results = {
            'file_info': {},
            'sections': [],
            'imports': {},
            'exports': [],
            'resources': [],
            'indicators': [],
            'risk_score': 0,
            'classification': 'UNKNOWN',
            'behaviors': [],
            'strings': [],
            'certificates': {},
            'tls_callbacks': [],
            'debug_info': {},
            'anti_analysis': [],
            'packer_info': {},
            'yara_matches': [],
            'ml_classification': None,
            'entropy_analysis': {},
            'disassembly': {}
        }
        
        # Try to parse as PE file
        if self.data[:2] == b'MZ':
            try:
                self.pe = pefile.PE(data=self.data)
                self.results['file_info']['pe_valid'] = True
                logger.info(f"Successfully parsed PE file: {self.filename}")
            except Exception as e:
                logger.error(f"PE parse error: {e}")
                self.results['file_info']['pe_valid'] = False
        else:
            self.results['file_info']['pe_valid'] = False
            logger.warning(f"File does not appear to be a PE executable: {self.filename}")

    def _entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        entropy = 0
        try:
            for x in range(256):
                p = data.count(x) / len(data)
                if p > 0:
                    entropy += -p * math.log2(p)
        except:
            return 0.0
        return entropy

    def _hex_dump(self, data: bytes, length: int = 16) -> str:
        """Create hex dump for debugging"""
        result = []
        for i in range(0, min(len(data), 256), length):
            chunk = data[i:i+length]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            result.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
        return '\n'.join(result)

    def header(self, title: str):
        """Print formatted section header"""
        print(f"\n{'='*80}")
        print(f"  {title}")
        print(f"{'='*80}")

    def _resolve_api_name(self, address: int) -> Optional[str]:
        """Resolve address to API name if possible"""
        if not self.pe:
            return None
        
        # Check imports for matching RVA
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if hasattr(imp, 'address') and imp.address:
                            if imp.address == address:
                                try:
                                    api_name = imp.name.decode('utf-8', errors='ignore')
                                    return f"{dll_name}!{api_name}"
                                except:
                                    pass
                except:
                    pass
        return None

    # ============ ANALYSIS MODULES ============

    def basic_info(self):
        """Enhanced basic file information with additional metadata"""
        self.header("BASIC FILE INFORMATION")
        
        # Calculate hashes
        md5_hash = hashlib.md5(self.data).hexdigest()
        sha1_hash = hashlib.sha1(self.data).hexdigest()
        sha256_hash = hashlib.sha256(self.data).hexdigest()
        sha512_hash = hashlib.sha512(self.data).hexdigest()
        
        print(f"  Filename:          {self.filename}")
        print(f"  File Size:         {self.filesize:,} bytes ({self.filesize/1024:.1f} KB)")
        print(f"  MD5:               {md5_hash}")
        print(f"  SHA1:              {sha1_hash}")
        print(f"  SHA256:            {sha256_hash}")
        print(f"  SHA512:            {sha512_hash[:16]}...")
        
        # Store hashes for later
        self.results['file_info']['hashes'] = {
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash,
            'sha512': sha512_hash
        }
        
        # MIME type detection
        if MAGIC_AVAILABLE:
            try:
                mime = magic.from_buffer(self.data, mime=True)
                print(f"  MIME Type:         {mime}")
                self.results['file_info']['mime'] = mime
            except:
                pass
        
        # Check for multiple MZ headers (binder detection)
        mz_count = len(re.findall(b'MZ', self.data))
        if mz_count > 1:
            print(f"  [!] Multiple MZ headers: {mz_count} (possible binder)")
            self.results['indicators'].append(f"Multiple MZ headers ({mz_count}) - potential file binder")
        
        # PE-specific information
        if self.pe:
            print(f"  Type:              PE Executable")
            print(f"  Machine:           {hex(self.pe.FILE_HEADER.Machine)}")
            print(f"  Number of Sections: {self.pe.FILE_HEADER.NumberOfSections}")
            
            # Timestamp analysis
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            if timestamp:
                try:
                    dt = datetime.datetime.fromtimestamp(timestamp)
                    print(f"  Compile Date:      {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                    # Check for suspicious date (future or very old)
                    if dt.year > datetime.datetime.now().year + 1:
                        print(f"    [!] Future timestamp! (possible tampering)")
                        self.results['indicators'].append("Future compile timestamp")
                    elif dt.year < 2000:
                        print(f"    [!] Very old timestamp (possible tampering)")
                        self.results['indicators'].append("Very old compile timestamp")
                except:
                    print(f"  Compile Date:      {timestamp}")
            
            # Entry point information
            entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            print(f"  Entry Point RVA:   {hex(entry_rva)}")
            print(f"  Image Base:        {hex(image_base)}")
            print(f"  Entry Point VA:    {hex(image_base + entry_rva)}")
            
            # Architecture detection
            arch = "x64" if self.pe.FILE_HEADER.Machine == 0x8664 else "x86"
            print(f"  Architecture:      {arch}")
            
            # Subsystem
            subsystem = self.pe.OPTIONAL_HEADER.Subsystem
            subsystem_names = {
                1: "Native", 2: "Windows GUI", 3: "Windows CUI", 
                7: "POSIX", 9: "Windows CE", 10: "EFI"
            }
            print(f"  Subsystem:         {subsystem_names.get(subsystem, f'Unknown ({subsystem})')}")
            
            # DLL characteristics
            dll_char = self.pe.OPTIONAL_HEADER.DllCharacteristics
            if dll_char:
                flags = []
                if dll_char & 0x0040: flags.append("ASLR")
                if dll_char & 0x0080: flags.append("DEP")
                if dll_char & 0x0100: flags.append("Integrity Check")
                if dll_char & 0x0200: flags.append("NX Compatible")
                if dll_char & 0x0400: flags.append("Control Flow Guard")
                if flags:
                    print(f"  DLL Flags:         {', '.join(flags)}")
            
            # Store PE info
            self.results['file_info']['pe'] = {
                'machine': hex(self.pe.FILE_HEADER.Machine),
                'entry_point': hex(entry_rva),
                'image_base': hex(image_base),
                'architecture': arch,
                'subsystem': subsystem_names.get(subsystem, 'Unknown'),
                'sections': self.pe.FILE_HEADER.NumberOfSections
            }

    def section_analysis(self):
        """Enhanced section analysis with advanced metrics"""
        if not self.pe:
            return
        
        self.header("DETAILED SECTION ANALYSIS")
        
        print(f"  {'Name':<12} {'VSize':<10} {'RSize':<10} {'Entropy':<9} {'Perms':<8} {'Entropy Trend':<12} {'Flags'}")
        print(f"  {'-'*85}")
        
        section_data = []
        high_entropy_count = 0
        
        for section in self.pe.sections:
            try:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                virt_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                
                # Get section data
                section_data_bytes = section.get_data()
                entropy = self._entropy(section_data_bytes) if section_data_bytes else 0.0
                
                # Calculate entropy in chunks for trend analysis
                entropy_trend = ""
                if section_data_bytes and len(section_data_bytes) > 1024:
                    chunk_size = len(section_data_bytes) // 4
                    entropies = []
                    for i in range(0, len(section_data_bytes), chunk_size):
                        chunk = section_data_bytes[i:i+chunk_size]
                        if chunk:
                            entropies.append(self._entropy(chunk))
                    
                    if len(entropies) > 1:
                        trend = []
                        for i in range(1, len(entropies)):
                            if entropies[i] > entropies[i-1] + 0.1:
                                trend.append("↑")
                            elif entropies[i] < entropies[i-1] - 0.1:
                                trend.append("↓")
                            else:
                                trend.append("→")
                        entropy_trend = ''.join(trend[:4])
                
                # Section permissions
                perms = []
                if section.Characteristics & 0x20000000: perms.append("X")
                if section.Characteristics & 0x40000000: perms.append("R")
                if section.Characteristics & 0x80000000: perms.append("W")
                perm_str = ''.join(perms) if perms else "NONE"
                
                # Suspicious flags
                flags = []
                if entropy > 7.5:
                    flags.append("[!HIGH ENTROPY]")
                    high_entropy_count += 1
                if 'W' in perm_str and 'X' in perm_str:
                    flags.append("[!WX]")
                    self.results['indicators'].append(f"WX section: {name}")
                if raw_size == 0 and virt_size > 0:
                    flags.append("[!UNINIT]")
                if virt_size > raw_size * 5 and raw_size > 0:
                    flags.append("[!UNPACKED]")
                
                # Check for common packer section names
                packer_sections = {
                    '.upx': 'UPX', '.upx1': 'UPX', '.upx2': 'UPX',
                    '.aspack': 'ASPack', '.mpress': 'MPRESS', 
                    '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
                    '.themida': 'Themida', '.enigma': 'Enigma'
                }
                
                if name.lower() in packer_sections:
                    flags.append(f"[PACKER: {packer_sections[name.lower()]}]")
                    self.results['packer_info'][name] = packer_sections[name.lower()]
                
                print(f"  {name:<12} {virt_size:<10} {raw_size:<10} {entropy:<8.3f} {perm_str:<8} {entropy_trend:<12} {' '.join(flags)}")
                
                # Store for later analysis
                section_data.append({
                    'name': name,
                    'virtual_size': virt_size,
                    'raw_size': raw_size,
                    'entropy': entropy,
                    'entropy_trend': entropy_trend,
                    'permissions': perm_str,
                    'flags': flags,
                    'data_size': len(section_data_bytes) if section_data_bytes else 0
                })
                
            except Exception as e:
                logger.debug(f"Error analyzing section: {e}")
        
        self.results['sections'] = section_data
        
        # Calculate overall file entropy
        total_entropy = self._entropy(self.data)
        print(f"\n  Overall File Entropy: {total_entropy:.3f}")
        if total_entropy > 7.8:
            print(f"  [!] HIGH OVERALL ENTROPY - File is likely packed/encrypted")
            self.results['indicators'].append(f"High overall entropy: {total_entropy:.2f}")

    def import_analysis(self):
        """Enhanced import analysis with malware API categorization"""
        if not self.pe:
            return
        
        self.header("IMPORT ANALYSIS")
        
        # Comprehensive malware API categories
        suspicious_apis = {
            'Process Manipulation': [
                'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                'OpenProcess', 'TerminateProcess', 'CreateProcess',
                'CreateToolhelp32Snapshot', 'Thread32First', 'Thread32Next',
                'Process32First', 'Process32Next', 'NtCreateThreadEx',
                'NtOpenProcess', 'NtQueryInformationProcess'
            ],
            'Memory Manipulation': [
                'VirtualProtect', 'VirtualAlloc', 'VirtualFree',
                'HeapCreate', 'HeapAlloc', 'GlobalAlloc',
                'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
                'RtlCreateHeap', 'RtlAllocateHeap'
            ],
            'Registry Operations': [
                'RegCreateKeyEx', 'RegSetValueEx', 'RegDeleteKey',
                'RegOpenKeyEx', 'RegQueryValueEx', 'RegEnumKey',
                'RegDeleteValue', 'RegCreateKey', 'RegFlushKey'
            ],
            'Network Communication': [
                'socket', 'connect', 'send', 'recv', 'WSASocket',
                'WSAStartup', 'WSAConnect', 'WSASend', 'WSARecv',
                'URLDownloadToFile', 'InternetOpen', 'InternetConnect',
                'HttpOpenRequest', 'HttpSendRequest', 'WinHttpOpen',
                'WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpSendRequest'
            ],
            'Persistence': [
                'CreateService', 'OpenSCManager', 'StartService',
                'RegCreateKeyEx', 'RegSetValueEx', 'SchTaskCreate',
                'CoInitializeEx', 'CoCreateInstance'
            ],
            'Anti-Debug': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'IsDebugged', 'NtQueryInformationProcess',
                'OutputDebugString', 'GetTickCount', 'QueryPerformanceCounter',
                'NtSetInformationThread', 'SetUnhandledExceptionFilter'
            ],
            'Keylogging': [
                'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
                'GetKeyboardState', 'GetForegroundWindow', 'GetWindowText',
                'CallNextHookEx', 'UnhookWindowsHookEx'
            ],
            'File Operations': [
                'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
                'MoveFile', 'CopyFile', 'FindFirstFile', 'FindNextFile',
                'SetFileAttributes', 'GetFileAttributes'
            ],
            'Code Injection': [
                'CreateRemoteThread', 'QueueUserAPC', 'SetWindowsHookEx',
                'WriteProcessMemory', 'VirtualAllocEx', 'NtCreateThreadEx',
                'RtlCreateUserThread', 'ZwCreateThreadEx'
            ],
            'Information Stealing': [
                'GetClipboardData', 'GetForegroundWindow', 'GetWindowText',
                'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
                'GetSystemMetrics', 'GetComputerName', 'GetUserName'
            ],
            'Remote Control': [
                'WSASocket', 'socket', 'connect', 'accept', 'listen',
                'WSAAsyncSelect', 'WSAEventSelect', 'WSAAsyncSocket'
            ],
            'Encryption': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
                'CryptGenKey', 'CryptExportKey', 'CryptImportKey',
                'BCryptEncrypt', 'BCryptDecrypt', 'BCryptOpenAlgorithmProvider'
            ],
            'Privilege Escalation': [
                'OpenProcessToken', 'LookupPrivilegeValue', 'AdjustTokenPrivileges',
                'CreateProcessAsUser', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser',
                'SetThreadToken', 'RevertToSelf'
            ],
            'Sandbox Detection': [
                'GetSystemMetrics', 'GetSystemInfo', 'GetProcessorArchitecture',
                'GetTickCount', 'QueryPerformanceCounter', 'RDTSC',
                'cpuid', 'GetCurrentProcessorNumber'
            ]
        }
        
        found_imports = defaultdict(set)
        total_imports = 0
        import_list = []
        
        # Parse imports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    dll_imports = []
                    
                    for imp in entry.imports:
                        if imp.name:
                            total_imports += 1
                            api = imp.name.decode('utf-8', errors='ignore')
                            dll_imports.append(api)
                            import_list.append((dll, api))
                            
                            # Check against suspicious API list
                            for category, apis in suspicious_apis.items():
                                if api in apis:
                                    found_imports[category].add(f"{dll}!{api}")
                                    
                                    # Add to behaviors
                                    if api in ['CreateRemoteThread', 'VirtualAllocEx']:
                                        self.results['behaviors'].append("Process Injection")
                                    if api in ['RegCreateKeyEx', 'RegSetValueEx']:
                                        self.results['behaviors'].append("Registry Persistence")
                                    if api in ['CreateService', 'OpenSCManager']:
                                        self.results['behaviors'].append("Service Installation")
                                    if any(api in apis for apis in suspicious_apis['Network Communication']):
                                        self.results['behaviors'].append("Network Activity")
                                    if api in ['SetWindowsHookEx', 'GetAsyncKeyState']:
                                        self.results['behaviors'].append("Keylogging")
                                    if api in ['CryptEncrypt', 'CryptDecrypt']:
                                        self.results['behaviors'].append("Encryption Usage")
                                    if api in ['OpenProcessToken', 'AdjustTokenPrivileges']:
                                        self.results['behaviors'].append("Privilege Escalation")
                                    if api in ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']:
                                        self.results['behaviors'].append("Anti-Debugging")
                                    if api in ['GetAsyncKeyState', 'SetWindowsHookEx']:
                                        self.results['behaviors'].append("Keylogging")
                
                except Exception as e:
                    logger.debug(f"Error parsing imports: {e}")
        
        print(f"  Total Imports: {total_imports}")
        
        # Display categorized suspicious imports
        if found_imports:
            print(f"\n  [ALERT] Suspicious API Usage Found!")
            for category, apis in sorted(found_imports.items()):
                print(f"\n  [{category}] ({len(apis)} found)")
                for api in sorted(apis)[:10]:
                    print(f"    - {api}")
                    if len(apis) > 10:
                        print(f"    ... and {len(apis)-10} more")
        else:
            print("\n  No suspicious imports detected")
        
        # Store import data
        self.results['imports'] = {
            'total': total_imports,
            'suspicious': {cat: list(apis) for cat, apis in found_imports.items()}
        }

    def export_analysis(self):
        """Analyze exported functions for potential malicious exports"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return
        
        self.header("EXPORT ANALYSIS")
        
        suspicious_exports = [
            'Install', 'Execute', 'Main', 'ServiceMain', 'DriverEntry',
            'Start', 'Run', 'Load', 'Inject', 'Exploit', 'Payload',
            'DllInstall', 'DllRegisterServer', 'DllUnregisterServer',
            'MainEntry', 'RunMe', 'StartService', 'Init'
        ]
        
        exports = []
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8', errors='ignore')
                exports.append({
                    'name': name,
                    'address': hex(exp.address),
                    'ordinal': exp.ordinal
                })
                
                if any(s in name for s in suspicious_exports):
                    print(f"  [!] Suspicious export: {name} at {hex(exp.address)}")
        
        if exports:
            print(f"\n  Total Exports: {len(exports)}")
            print("\n  All Exports:")
            for exp in exports[:20]:
                print(f"    {exp['name']:30} {exp['address']}")
            if len(exports) > 20:
                print(f"    ... and {len(exports)-20} more")
            
            self.results['exports'] = exports
        else:
            print("  No exports found (typical for executables)")

    def resource_analysis(self):
        """Comprehensive resource analysis for embedded payloads"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return
        
        self.header("RESOURCE ANALYSIS")
        
        resource_types = {
            1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON',
            4: 'RT_MENU', 5: 'RT_DIALOG', 6: 'RT_STRING',
            7: 'RT_FONTDIR', 8: 'RT_FONT', 9: 'RT_ACCELERATOR',
            10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE', 12: 'RT_GROUP_CURSOR',
            14: 'RT_GROUP_ICON', 16: 'RT_VERSION', 17: 'RT_DLGINCLUDE',
            19: 'RT_PLUGPLAY', 20: 'RT_VXD', 21: 'RT_ANICURSOR',
            22: 'RT_ANIICON', 24: 'RT_MANIFEST', 240: 'RT_HTML'
        }
        
        total_resources = 0
        suspicious_resources = []
        embedded_pes = []
        
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry_type in entry.directory.entries:
                try:
                    res_type_id = entry_type.id
                    res_type = resource_types.get(res_type_id, f"Unknown ({res_type_id})")
                    
                    for lang_entry in entry_type.directory.entries:
                        try:
                            data_rva = lang_entry.data.struct.OffsetToData
                            size = lang_entry.data.struct.Size
                            total_resources += 1
                            
                            # Extract resource data
                            data = None
                            try:
                                data = self.pe.get_data(data_rva, size)
                            except:
                                pass
                            
                            if data:
                                entropy = self._entropy(data)
                                
                                # Check for PE payload
                                if data[:2] == b'MZ':
                                    embedded_pes.append(f"Embedded PE in {res_type} ({size} bytes)")
                                    suspicious_resources.append(f"EMBEDDED PE in {res_type}")
                                    print(f"  [!!!] EMBEDDED PE IN RESOURCE: {res_type}")
                                    print(f"    Size: {size} bytes")
                                    print(f"    Entropy: {entropy:.2f}")
                                    continue
                                
                                print(f"  {res_type}: Size={size} bytes, Entropy={entropy:.2f}")
                                
                                # Check for suspicious resource types
                                if res_type_id == 10:  # RT_RCDATA
                                    if entropy > 7.5:
                                        suspicious_resources.append(f"RT_RCDATA with high entropy ({entropy:.2f}) - possible encrypted payload")
                                    elif len(data) > 10000:
                                        suspicious_resources.append(f"Large RT_RCDATA ({size} bytes) - possible embedded payload")
                                
                                # Check for encrypted data
                                if entropy > 7.8 and len(data) > 5000:
                                    suspicious_resources.append(f"High entropy blob in {res_type} ({size} bytes, entropy={entropy:.2f})")
                                
                                # Store resource info
                                self.results['resources'].append({
                                    'type': res_type,
                                    'size': size,
                                    'entropy': entropy,
                                    'rva': hex(data_rva)
                                })
                                
                        except Exception as e:
                            logger.debug(f"Error parsing resource lang entry: {e}")
                            
                except Exception as e:
                    logger.debug(f"Error parsing resource type: {e}")
        
        print(f"\n  Total Resources: {total_resources}")
        
        if embedded_pes:
            print(f"\n  [CRITICAL] Embedded PE Files Found:")
            for item in embedded_pes:
                print(f"    [!] {item}")
                self.results['indicators'].append(item)
        
        if suspicious_resources:
            print(f"\n  [ALERT] Suspicious Resources Found:")
            for item in suspicious_resources[:10]:
                print(f"    [!] {item}")
                self.results['indicators'].append(f"Suspicious resource: {item}")

    def tls_analysis(self):
        """Analyze TLS callbacks (run before entry point)"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
            return
        
        self.header("TLS CALLBACK ANALYSIS")
        
        tls = self.pe.DIRECTORY_ENTRY_TLS
        if tls and hasattr(tls, 'struct'):
            print(f"  [!] TLS Callbacks Found! These execute BEFORE the main entry point")
            self.results['indicators'].append("TLS callbacks present (run before entry point)")
            
            # Get callback array address
            if hasattr(tls.struct, 'AddressOfCallBacks'):
                callback_array_rva = tls.struct.AddressOfCallBacks
                print(f"  Callback array at: {hex(callback_array_rva)}")
                
                # Read callback addresses
                try:
                    offset = self.pe.get_offset_from_rva(callback_array_rva)
                    if offset:
                        callbacks = []
                        pos = offset
                        while True:
                            # Read callback address (4 or 8 bytes depending on architecture)
                            arch_size = 8 if self.pe.FILE_HEADER.Machine == 0x8664 else 4
                            callback_data = self.data[pos:pos+arch_size]
                            if len(callback_data) < arch_size:
                                break
                            
                            callback_addr = int.from_bytes(callback_data, 'little')
                            if callback_addr == 0:
                                break
                            
                            callbacks.append(hex(callback_addr))
                            pos += arch_size
                        
                        for idx, callback in enumerate(callbacks):
                            print(f"    Callback {idx+1}: {callback}")
                            
                        self.results['tls_callbacks'] = callbacks
                        
                except Exception as e:
                    logger.debug(f"Error parsing TLS callbacks: {e}")
        else:
            print("  No TLS callbacks found")

    def certificate_analysis(self):
        """Analyze digital signatures and certificates"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
            return
        
        self.header("CERTIFICATE ANALYSIS")
        
        security = self.pe.DIRECTORY_ENTRY_SECURITY
        if security:
            print(f"  [INFO] Digital Certificate Present")
            print(f"  Certificate Size: {len(security)} bytes")
            
            # Try to extract basic certificate info
            try:
                # Check if certificate is valid (simplified)
                cert_data = security.get_data()
                if cert_data:
                    # Look for common certificate info
                    cert_info = {}
                    
                    # Simple check for common issuer names (pattern matching)
                    patterns = {
                        b'CN=': 'Common Name',
                        b'O=': 'Organization',
                        b'OU=': 'Organizational Unit',
                        b'C=': 'Country',
                        b'ST=': 'State',
                        b'L=': 'Location'
                    }
                    
                    for pattern, label in patterns.items():
                        if pattern in cert_data:
                            # Extract substring
                            idx = cert_data.find(pattern)
                            end = cert_data.find(b'\x00', idx)
                            if end > idx:
                                value = cert_data[idx:end].decode('utf-8', errors='ignore')
                                cert_info[label] = value
                    
                    if cert_info:
                        print("\n  Certificate Information:")
                        for label, value in cert_info.items():
                            print(f"    {label}: {value}")
                    
                    self.results['certificates'] = cert_info
            except Exception as e:
                logger.debug(f"Error parsing certificate: {e}")
        else:
            print("  [WARNING] No digital certificate present")
            self.results['indicators'].append("No digital certificate (unsigned)")

    def pe_rich_header(self):
        """Analyze Rich Header for compiler/linker information"""
        if not self.pe:
            return
        
        self.header("RICH HEADER ANALYSIS")
        
        try:
            # Rich header parsing (simplified)
            if hasattr(self.pe, 'RICH_HEADER') and self.pe.RICH_HEADER:
                rich = self.pe.RICH_HEADER
                print(f"  Rich Header Found!")
                
                # Tool information
                tool_list = []
                for entry in rich._entries:
                    if entry.toolid and entry.version:
                        tool_list.append(f"ToolID={hex(entry.toolid)}, Version={entry.version}, Count={entry.count}")
                        print(f"    {tool_list[-1]}")
                
                self.results['rich_header'] = tool_list
            else:
                print("  No Rich Header found (compilation metadata missing)")
                
        except Exception as e:
            logger.debug(f"Error parsing Rich Header: {e}")

    def debug_info_analysis(self):
        """Analyze debug information present in the PE"""
        if not self.pe:
            return
        
        self.header("DEBUG INFORMATION")
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            debug_dir = self.pe.DIRECTORY_ENTRY_DEBUG
            if debug_dir:
                print(f"  Debug directory found with {len(debug_dir)} entries")
                
                for idx, debug_entry in enumerate(debug_dir):
                    try:
                        # Parse debug entry
                        debug_type = debug_entry.struct.Type
                        debug_types = {
                            1: 'IMAGE_DEBUG_TYPE_COFF',
                            2: 'IMAGE_DEBUG_TYPE_CODEVIEW',
                            3: 'IMAGE_DEBUG_TYPE_FPO',
                            4: 'IMAGE_DEBUG_TYPE_MISC',
                            5: 'IMAGE_DEBUG_TYPE_EXCEPTION',
                            6: 'IMAGE_DEBUG_TYPE_FIXUP',
                            7: 'IMAGE_DEBUG_TYPE_OMAP_TO_SRC',
                            8: 'IMAGE_DEBUG_TYPE_OMAP_FROM_SRC',
                            9: 'IMAGE_DEBUG_TYPE_BORLAND',
                            10: 'IMAGE_DEBUG_TYPE_RESERVED10',
                            11: 'IMAGE_DEBUG_TYPE_CLSID'
                        }
                        
                        print(f"\n  Entry {idx+1}:")
                        print(f"    Type: {debug_types.get(debug_type, f'Unknown ({debug_type})')}")
                        print(f"    Size: {debug_entry.struct.SizeOfData}")
                        print(f"    RVA: {hex(debug_entry.struct.AddressOfRawData)}")
                        print(f"    Timestamp: {debug_entry.struct.TimeDateStamp}")
                        
                        # Try to extract CodeView info
                        if debug_type == 2:  # CodeView
                            try:
                                offset = self.pe.get_offset_from_rva(debug_entry.struct.AddressOfRawData)
                                if offset:
                                    cv_data = self.data[offset:offset+debug_entry.struct.SizeOfData]
                                    if cv_data:
                                        # Check for PDB path
                                        pdb_match = re.search(b'[A-Za-z]:\\\\[^\\x00]+\.pdb', cv_data)
                                        if pdb_match:
                                            pdb_path = pdb_match.group().decode('utf-8', errors='ignore')
                                            print(f"    PDB Path: {pdb_path}")
                                            
                                            # PDB path analysis
                                            if 'visualstudio' in pdb_path.lower():
                                                print(f"      [+] Visual Studio build")
                                            if 'release' in pdb_path.lower():
                                                print(f"      [+] Release build")
                                            elif 'debug' in pdb_path.lower():
                                                print(f"      [+] Debug build")
                            except:
                                pass
                    except Exception as e:
                        logger.debug(f"Error parsing debug entry: {e}")
            else:
                print("  No debug information found")
        else:
            print("  No debug directory present")

    def string_analysis(self, min_length: int = 4):
        """Enhanced string analysis with classification and scoring"""
        self.header("STRING ANALYSIS AND CLASSIFICATION")
        
        # Find ASCII strings
        strings = set()
        for match in re.finditer(b'[\x20-\x7e]{%d,}' % min_length, self.data):
            try:
                s = match.group().decode('ascii', errors='ignore')
                if s.strip() and not all(c == '\x00' for c in s):
                    strings.add(s)
            except:
                pass
        
        # Find Unicode strings
        for match in re.finditer(b'(?:[\x20-\x7e]\x00){%d,}' % min_length, self.data):
            try:
                s = match.group().decode('utf-16-le', errors='ignore')
                if s.strip() and not all(c == '\x00' for c in s):
                    strings.add(s)
            except:
                pass
        
        # Comprehensive pattern categories
        patterns = {
            'URL': r'https?://[^\s<>"]+|www\.[^\s<>"]+',
            'IP Address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?',
            'Registry Path': r'(?:HKEY_|HKLM|HKCU|HKCR|HKU)[A-Z_]*\\[^\\\s]*(?:\\[^\\\s]*)*',
            'Shell Command': r'(?:cmd|powershell|bash|sh|wmic|rundll32|regsvr32)\.exe',
            'File Path': r'[A-Za-z]:\\[^<>"|?*\n\r]*\.(?:exe|dll|sys|tmp|dat|cfg|ini|log)',
            'Domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            'Base64': r'[A-Za-z0-9+/]{30,}={0,2}',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Mutex': r'(?:Global|Local|Session)\\?[^\\\s]+',
            'Password': r'(?:pass|pwd|secret|key|cred|auth)[^\s]*',
            'API Call': r'[A-Za-z_][A-Za-z0-9_]*Ex?[AW]?',
            'File Operation': r'(?:Create|Open|Read|Write|Delete|Move|Copy)File',
            'Registry API': r'Reg(?:Create|Open|Delete|Query|Set|Enum|Get)Value',
            'Network API': r'(?:socket|connect|send|recv|WSASocket|WinHttp|Internet)',
            'Process API': r'(?:Create|Open|Terminate|Suspend|Resume)Process',
            'Thread API': r'(?:Create|Open|Terminate|Suspend|Resume)Thread',
            'Memory API': r'(?:Virtual|Heap|Global|Local)(?:Alloc|Free|Protect|Lock)',
            'System API': r'(?:Get|Set|Query)System(?:Info|Time|Metrics)',
            'Debug API': r'(?:IsDebuggerPresent|CheckRemoteDebuggerPresent)',
            'Command Line': r'--[a-zA-Z-]+|\-[a-zA-Z]',
            'Cryptographic': r'[A-Fa-f0-9]{32,64}',
            'Persistence': r'(?:SOFTWARE|SYSTEM|Microsoft|Windows|CurrentVersion)(?:\\[^\\]+)+'
        }
        
        # Score strings based on suspicious patterns
        scored_strings = []
        for s in strings:
            if len(s) > 200 or len(s) < min_length:
                continue
            
            score = 0
            categories = set()
            matched_patterns = []
            
            for cat, pattern in patterns.items():
                if re.search(pattern, s, re.IGNORECASE):
                    score += 1
                    categories.add(cat)
                    matched_patterns.append(cat)
            
            if score > 0:
                # Additional scoring factors
                if len(s) > 50:
                    score += 1
                if re.search(r'[A-Za-z0-9+/]{30,}={0,2}', s):
                    score += 2  # Base64-like
                if re.search(r'[A-Fa-f0-9]{32,}', s):
                    score += 2  # Hash-like
                
                scored_strings.append({
                    'string': s,
                    'score': score,
                    'categories': categories,
                    'patterns': matched_patterns,
                    'length': len(s)
                })
        
        # Sort by score
        scored_strings.sort(key=lambda x: x['score'], reverse=True)
        
        # Display results
        if scored_strings:
            print(f"\n  Top {min(30, len(scored_strings))} Suspicious Strings:")
            for i, item in enumerate(scored_strings[:30], 1):
                print(f"\n  {i:2}. [Score: {item['score']}] [{', '.join(sorted(item['categories']))}]")
                display_str = item['string'][:150]
                if len(item['string']) > 150:
                    display_str += "..."
                print(f"      {display_str}")
                
                # Show offset if we know it (optional)
                # Could add position tracking
        else:
            print("  No strings matched suspicious patterns")
        
        # Store results
        self.results['strings'] = scored_strings[:50]  # Store top 50

    def anti_debug_vm_detection(self):
        """Comprehensive anti-debug and VM detection analysis"""
        self.header("ANTI-DEBUG & VM DETECTION")
        
        detection_patterns = {
            # VM detection patterns
            'vbox': 'VirtualBox detection',
            'vmware': 'VMware detection',
            'vmscsi': 'VMware storage',
            'qemu': 'QEMU detection',
            'xen': 'Xen detection',
            'parallels': 'Parallels detection',
            
            # VM device patterns
            '\\\\.\\HGFS': 'VMware shared folders',
            '\\\\.\\VBoxMiniRdrDN': 'VirtualBox shared folders',
            'VBoxGuest': 'VirtualBox guest additions',
            'VBoxMouse': 'VirtualBox mouse driver',
            'VBoxVideo': 'VirtualBox video driver',
            
            # Debug detection
            'IsDebuggerPresent': 'Debugger detection',
            'CheckRemoteDebuggerPresent': 'Remote debugger detection',
            'NtQueryInformationProcess': 'Process information query (anti-debug)',
            'NtSetInformationThread': 'Thread information (anti-debug)',
            'OutputDebugString': 'Debug string (anti-debug)',
            'SetUnhandledExceptionFilter': 'Exception handler (anti-debug)',
            
            # Debugger artifact strings
            'OllyDbg': 'OllyDbg debugger detection',
            'x64dbg': 'x64dbg debugger detection',
            'Immunity Debugger': 'Immunity debugger detection',
            'WinDbg': 'WinDbg detection',
            'DbgView': 'DebugView detection',
            'procdump': 'ProcDump detection',
            'IDA Pro': 'IDA Pro detection',
            
            # Timing checks
            'GetTickCount': 'Timing-based anti-debug',
            'QueryPerformanceCounter': 'Timing-based anti-debug',
            'rdtsc': 'CPU timing check (VM detection)',
            
            # Sandbox detection
            'sandbox': 'Sandbox environment detection',
            'cuckoo': 'Cuckoo sandbox detection',
            'analyzer': 'Sandbox analyzer detection',
            
            # Debugger APIs
            'DebugBreak': 'Debug break',
            'DbgBreakPoint': 'Debug breakpoint',
            'DbgUserBreakPoint': 'User breakpoint',
            
            # Process detection
            'process32first': 'Process enumeration (anti-debug)',
            'toolhelp32snapshot': 'Process snapshot (anti-debug)',
            'EnumProcesses': 'Process enumeration (anti-debug)',
            
            # Unusual access patterns
            '\\\\.\\NULL': 'NULL device access (anti-debug)',
            '\\\\.\\NUL': 'NULL device access (anti-debug)',
        }
        
        found_patterns = []
        
        # Search in file data
        for pattern, description in detection_patterns.items():
            if pattern.encode() in self.data:
                found_patterns.append(f"  [!] {description}: '{pattern}'")
                if 'VM' in description or 'Virtual' in description:
                    self.results['anti_analysis'].append(description)
        
        # Search in imports for anti-debug API
        if self.pe and hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    for imp in entry.imports:
                        if imp.name:
                            api = imp.name.decode('utf-8', errors='ignore')
                            for pattern, description in detection_patterns.items():
                                if pattern.lower() == api.lower():
                                    found_patterns.append(f"  [!] {description}: '{api}' (imported)")
                                    self.results['anti_analysis'].append(description)
                except:
                    pass
        
        if found_patterns:
            print("\n  Anti-Analysis Techniques Detected:")
            for pattern in sorted(set(found_patterns)):
                print(pattern)
            print(f"\n  Total anti-analysis techniques: {len(set(found_patterns))}")
        else:
            print("  No obvious anti-analysis techniques detected")
        
        return found_patterns

    def packer_detection(self):
        """Advanced packer detection using multiple techniques"""
        if not self.pe:
            return
        
        self.header("PACKER DETECTION")
        
        packer_info = {
            'sections': [],
            'entropy': [],
            'imports': [],
            'entry_point': [],
            'pyinstaller': False
        }
        
        # Check for PyInstaller artifacts
        if b'PyInstaller' in self.data or b'_MEI' in self.data or b'pyi-windows' in self.data:
            packer_info['pyinstaller'] = True
            print("  [!!!] PYINSTALLER PACKED FILE DETECTED")
            print("    This file appears to be packed with PyInstaller")
            self.results['indicators'].append("PyInstaller packaged file")
        
        # Check for Python artifacts
        if b'python' in self.data.lower() or b'_py' in self.data:
            print("  [!] Python artifacts found")
            self.results['indicators'].append("Python-related artifacts found")
        
        # 1. Section-based detection
        for section in self.pe.sections:
            try:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                data = section.get_data()
                entropy = self._entropy(data) if data else 0.0
                
                # Known packer sections
                packer_patterns = {
                    '.upx': 'UPX',
                    '.upx1': 'UPX',
                    '.upx2': 'UPX',
                    '.aspack': 'ASPack',
                    '.mpress': 'MPRESS',
                    '.vmp0': 'VMProtect',
                    '.vmp1': 'VMProtect',
                    '.vmp2': 'VMProtect',
                    '.themida': 'Themida',
                    '.enigma': 'Enigma',
                    '.orel': 'Obsidium',
                    '.y0da': 'Yoda\'s Protector',
                    '.sec': 'SafeEngine',
                    '.PEP': 'PE Pack',
                    '.nsp': 'NSPack',
                    '.pack': 'Pack',
                    '.code': 'Code',
                    '.data': 'Data',
                    '.reloc': 'Relocation'
                }
                
                if name.lower() in packer_patterns:
                    packer_info['sections'].append(f"{name}: {packer_patterns[name.lower()]}")
                    
                # Check for high entropy sections (indicative of packing)
                if entropy > 7.5 and len(data) > 1024:
                    packer_info['entropy'].append(f"{name}: entropy={entropy:.2f}")
                    
            except:
                pass
        
        # 2. Import-based detection (packed files have minimal imports)
        import_count = 0
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                import_count += len(entry.imports)
        
        if import_count < 10:
            packer_info['imports'].append(f"Low import count ({import_count}) - possible packing")
        
        # 3. Entry point analysis
        try:
            ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            # Check if entry point is in the first section or a custom section
            ep_section = None
            for section in self.pe.sections:
                if section.contains_rva(ep_rva):
                    try:
                        ep_section = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                        break
                    except:
                        pass
            
            if ep_section and ep_section not in ['.text', 'CODE']:
                packer_info['entry_point'].append(f"Entry point in non-standard section: {ep_section}")
        except:
            pass
        
        # Display results
        if any(packer_info.values()):
            print("  Packing Indicators Found:")
            
            if packer_info['pyinstaller']:
                print("\n  [!!!] PYINSTALLER PACKED")
                print("    File is packaged with PyInstaller")
            
            if packer_info['sections']:
                print("\n  [SECTION INDICATORS]")
                for item in packer_info['sections']:
                    print(f"    - {item}")
            
            if packer_info['entropy']:
                print("\n  [HIGH ENTROPY SECTIONS]")
                for item in packer_info['entropy'][:5]:
                    print(f"    - {item}")
                if len(packer_info['entropy']) > 5:
                    print(f"    ... and {len(packer_info['entropy'])-5} more")
            
            if packer_info['imports']:
                print("\n  [IMPORT INDICATORS]")
                for item in packer_info['imports']:
                    print(f"    - {item}")
            
            if packer_info['entry_point']:
                print("\n  [ENTRY POINT INDICATORS]")
                for item in packer_info['entry_point']:
                    print(f"    - {item}")
            
            # Update packer info
            self.results['packer_info'] = packer_info
            
            # Add indicators
            if packer_info['sections'] or packer_info['entropy'] or packer_info['pyinstaller']:
                self.results['indicators'].append("Packed executable detected")
        else:
            print("  No packer indicators found (could still be custom packed)")

    def disassembly_analysis(self, count: int = 50):
        """Advanced disassembly with API resolution and pattern detection"""
        if not CAPSTONE_AVAILABLE or not self.pe:
            return
        
        self.header(f"ENTRY POINT DISASSEMBLY ({count} instructions)")
        
        try:
            entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_offset = self.pe.get_offset_from_rva(entry_rva)
            
            # Set up disassembler
            if self.pe.FILE_HEADER.Machine == 0x014c:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif self.pe.FILE_HEADER.Machine == 0x8664:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                print(f"  Unsupported architecture: {hex(self.pe.FILE_HEADER.Machine)}")
                return
            
            md.detail = True
            
            # Get entry point code
            code = self.data[entry_offset:entry_offset + min(count * 20, 2048)]
            instructions = []
            suspicious_sequences = []
            
            print(f"  Entry Point RVA: {hex(entry_rva)}, Offset: {hex(entry_offset)}\n")
            
            # Disassemble
            icount = 0
            for insn in md.disasm(code, entry_offset):
                if icount >= count:
                    break
                
                va = self.pe.OPTIONAL_HEADER.ImageBase + insn.address
                hex_bytes = ' '.join(f'{b:02x}' for b in insn.bytes)
                
                # Detect interesting patterns
                comment = ""
                mnemonic = insn.mnemonic
                op_str = insn.op_str
                
                # API call detection - try to resolve
                if mnemonic in ['call', 'jmp']:
                    if '[' in op_str or 'ptr' in op_str:
                        comment = " [indirect call]"
                    
                    # Try to resolve call target
                    if '0x' in op_str:
                        try:
                            target = int(op_str.split('0x')[-1], 16)
                            api_name = self._resolve_api_name(target)
                            if api_name:
                                comment += f" [{api_name}]"
                        except:
                            pass
                
                # Anti-debug patterns
                if mnemonic == 'cpuid':
                    comment = " [VM detection check]"
                    self.results['anti_analysis'].append("CPUID instruction (VM detection)")
                
                if mnemonic == 'int' and '0x2d' in op_str:
                    comment = " [debug breakpoint]"
                    self.results['anti_analysis'].append("INT 0x2D (anti-debug)")
                
                # Timing checks
                if mnemonic == 'rdtsc':
                    comment = " [timing check]"
                    self.results['anti_analysis'].append("RDTSC timing check")
                
                # Output instruction
                print(f"  {hex(va):<16} | {hex_bytes:<32} | {mnemonic:<10} {op_str:<30}{comment}")
                
                # Store instruction
                instructions.append({
                    'address': hex(va),
                    'bytes': hex_bytes,
                    'mnemonic': mnemonic,
                    'operands': op_str,
                    'comment': comment.strip()
                })
                
                icount += 1
            
            # Look for suspicious patterns in the disassembly
            if instructions:
                pattern_result = self._detect_malware_patterns(instructions)
                if pattern_result:
                    print(f"\n  [ALERT] Suspicious patterns detected:")
                    for pattern in pattern_result:
                        print(f"    [!] {pattern}")
            
            self.results['disassembly'] = {
                'entry_point_va': hex(self.pe.OPTIONAL_HEADER.ImageBase + entry_rva),
                'instructions': instructions,
                'suspicious_patterns': pattern_result if 'pattern_result' in locals() else []
            }
            
        except Exception as e:
            print(f"  Disassembly error: {e}")
            logger.debug(f"Disassembly error: {e}")

    def _detect_malware_patterns(self, instructions: List[Dict]) -> List[str]:
        """Detect common malware patterns in disassembly"""
        patterns = []
        
        # Check for common obfuscation patterns
        if len(instructions) >= 3:
            # XOR decryption pattern
            xor_pattern = 0
            for i in range(len(instructions) - 2):
                if ('xor' in instructions[i]['mnemonic'] and
                    'mov' in instructions[i+1]['mnemonic'] and
                    'inc' in instructions[i+2]['mnemonic']):
                    xor_pattern += 1
            
            if xor_pattern >= 2:
                patterns.append(f"Possible XOR decryption loop ({xor_pattern} occurrences)")
            
            # Get EIP pattern (common in shellcode)
            for i in range(len(instructions) - 1):
                if ('call' in instructions[i]['mnemonic'] and
                    'pop' in instructions[i+1]['mnemonic']):
                    patterns.append("call/pop pattern - possible get EIP technique")
                    break
        
        # Check for API hashing (common in malware)
        hash_pattern = 0
        for insn in instructions:
            if any(x in insn['mnemonic'] for x in ['shr', 'shl', 'ror', 'rol']):
                if any(x in insn['mnemonic'] for x in ['xor', 'add', 'sub']):
                    hash_pattern += 1
        
        if hash_pattern >= 5:
            patterns.append(f"Possible API hashing ({hash_pattern} operations)")
        
        # Check for anti-analysis techniques
        anti_techs = ['cpuid', 'rdtsc', 'int 0x2d']
        for tech in anti_techs:
            if any(tech in insn['mnemonic'] or tech in insn['operands'] 
                   for insn in instructions):
                patterns.append(f"Anti-analysis technique detected: {tech}")
        
        return patterns

    def behavioral_analysis(self):
        """Generate comprehensive behavioral analysis based on imports"""
        if not self.pe:
            return
        
        self.header("BEHAVIORAL ANALYSIS")
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("  No imports found")
            return
        
        # Build import set
        imports = set()
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode('utf-8', errors='ignore'))
        
        # Define behavior patterns with confidence levels
        behavior_patterns = {
            'File System Manipulation': {
                'apis': ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 
                        'MoveFile', 'CopyFile', 'SetFileAttributes'],
                'confidence': 0.5,
                'description': 'Reads, writes, or deletes files'
            },
            'Registry Manipulation': {
                'apis': ['RegCreateKeyEx', 'RegSetValueEx', 'RegDeleteKey',
                        'RegOpenKeyEx', 'RegQueryValueEx'],
                'confidence': 0.6,
                'description': 'Modifies Windows registry'
            },
            'Process Injection': {
                'apis': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                        'NtCreateThreadEx', 'QueueUserAPC'],
                'confidence': 0.8,
                'description': 'Injects code into other processes'
            },
            'Persistence Mechanism': {
                'apis': ['CreateService', 'RegCreateKeyEx', 'RegSetValueEx',
                        'SchTaskCreate', 'SetWindowsHookEx'],
                'confidence': 0.7,
                'description': 'Establishes persistence mechanism'
            },
            'Network Activity': {
                'apis': ['socket', 'connect', 'send', 'recv', 'WSASocket',
                        'WSAStartup', 'URLDownloadToFile', 'InternetOpen',
                        'WinHttpOpen'],
                'confidence': 0.7,
                'description': 'Performs network communication'
            },
            'Keylogging': {
                'apis': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
                        'GetKeyboardState', 'GetForegroundWindow'],
                'confidence': 0.75,
                'description': 'Captures keyboard input'
            },
            'Screen Capture': {
                'apis': ['GetDC', 'CreateCompatibleDC', 'BitBlt', 'StretchBlt',
                        'CreateCompatibleBitmap', 'GetPixel'],
                'confidence': 0.6,
                'description': 'Captures screen content'
            },
            'Encryption Usage': {
                'apis': ['CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
                        'BCryptEncrypt', 'BCryptDecrypt'],
                'confidence': 0.6,
                'description': 'Uses encryption functions'
            },
            'Privilege Escalation': {
                'apis': ['OpenProcessToken', 'LookupPrivilegeValue', 'AdjustTokenPrivileges',
                        'CreateProcessAsUser', 'DuplicateTokenEx'],
                'confidence': 0.7,
                'description': 'Attempts to elevate privileges'
            },
            'Information Theft': {
                'apis': ['GetClipboardData', 'GetWindowText', 'GetComputerName',
                        'GetUserName', 'GetSystemMetrics', 'GetVolumeInformation'],
                'confidence': 0.5,
                'description': 'Collects system information'
            },
            'Anti-Analysis': {
                'apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                        'NtQueryInformationProcess', 'SetUnhandledExceptionFilter'],
                'confidence': 0.6,
                'description': 'Uses anti-debugging techniques'
            }
        }
        
        detected_behaviors = []
        
        for behavior, pattern in behavior_patterns.items():
            found_apis = [api for api in pattern['apis'] if api in imports]
            if found_apis:
                confidence = min(1.0, pattern['confidence'] * (1 + len(found_apis) / 10))
                detected_behaviors.append({
                    'behavior': behavior,
                    'apis': found_apis,
                    'confidence': min(1.0, confidence),
                    'description': pattern['description']
                })
        
        if detected_behaviors:
            print("  [INFO] Detected Behaviors:")
            for behavior in sorted(detected_behaviors, key=lambda x: x['confidence'], reverse=True):
                print(f"\n    [{behavior['behavior']}] (Confidence: {behavior['confidence']*100:.0f}%)")
                print(f"    {behavior['description']}")
                print(f"    APIs: {', '.join(behavior['apis'][:5])}")
                if len(behavior['apis']) > 5:
                    print(f"    ... and {len(behavior['apis'])-5} more")
            
            # Store behaviors
            self.results['behaviors'] = detected_behaviors
        else:
            print("  No significant behaviors detected")

    def advanced_entropy_analysis(self):
        """Perform advanced entropy analysis across the entire file"""
        self.header("ADVANCED ENTROPY ANALYSIS")
        
        # Analyze entropy in chunks
        chunk_size = 4096
        chunks = []
        
        for i in range(0, len(self.data), chunk_size):
            chunk = self.data[i:i+chunk_size]
            if chunk:
                entropy = self._entropy(chunk)
                chunks.append({
                    'offset': i,
                    'size': len(chunk),
                    'entropy': entropy
                })
        
        if not chunks:
            print("  No data to analyze")
            return
        
        # Calculate statistics
        entropies = [c['entropy'] for c in chunks]
        avg_entropy = sum(entropies) / len(entropies)
        max_entropy = max(entropies)
        min_entropy = min(entropies)
        
        print(f"  Total chunks: {len(chunks)}")
        print(f"  Average entropy: {avg_entropy:.3f}")
        print(f"  Maximum entropy: {max_entropy:.3f}")
        print(f"  Minimum entropy: {min_entropy:.3f}")
        
        # Find suspicious regions
        high_entropy_regions = []
        for chunk in chunks:
            if chunk['entropy'] > 7.5:
                high_entropy_regions.append(chunk)
        
        if high_entropy_regions:
            print(f"\n  [!] High entropy regions found:")
            for region in high_entropy_regions[:10]:
                print(f"    Offset: {hex(region['offset'])} (entropy: {region['entropy']:.3f})")
            if len(high_entropy_regions) > 10:
                print(f"    ... and {len(high_entropy_regions)-10} more")
        
        # Look for entropy patterns
        entropy_trend = []
        for i in range(1, len(chunks)):
            diff = chunks[i]['entropy'] - chunks[i-1]['entropy']
            if diff > 0.5:
                entropy_trend.append(f"↑ {chunks[i]['offset']}")
            elif diff < -0.5:
                entropy_trend.append(f"↓ {chunks[i]['offset']}")
        
        if entropy_trend:
            print(f"\n  Entropy changes detected at:")
            for trend in entropy_trend[:5]:
                print(f"    {trend}")
        
        self.results['entropy_analysis'] = {
            'average': avg_entropy,
            'max': max_entropy,
            'min': min_entropy,
            'high_entropy_regions': high_entropy_regions[:20]
        }

    def yara_scan(self, rules_dir: Optional[str] = None):
        """Scan file with YARA rules"""
        if not YARA_AVAILABLE:
            print("  YARA not available - skipping scan")
            return
        
        self.header("YARA RULE SCAN")
        
        # Use provided rules directory or default
        if not rules_dir:
            rules_dir = self.config.get('yara_rules_dir', 'yara_rules')
        
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            print(f"  YARA rules directory not found: {rules_dir}")
            return
        
        # Find all .yar/.yara files
        rule_files = list(rules_path.glob('**/*.yar')) + list(rules_path.glob('**/*.yara'))
        
        if not rule_files:
            print(f"  No YARA rule files found in {rules_dir}")
            return
        
        print(f"  Found {len(rule_files)} rule files")
        
        try:
            # Compile rules
            rules = {}
            for rule_file in rule_files:
                try:
                    rules[str(rule_file)] = str(rule_file)
                except:
                    pass
            
            if not rules:
                print("  No valid rules to compile")
                return
            
            compiled_rules = yara.compile(filepaths=rules)
            
            # Scan file
            matches = compiled_rules.match(data=self.data)
            
            if matches:
                print(f"\n  [ALERT] {len(matches)} YARA matches found!")
                for match in matches:
                    print(f"\n    Rule: {match.rule}")
                    if hasattr(match, 'meta'):
                        if 'description' in match.meta:
                            print(f"    Description: {match.meta['description']}")
                        if 'author' in match.meta:
                            print(f"    Author: {match.meta['author']}")
                        if 'severity' in match.meta:
                            print(f"    Severity: {match.meta['severity']}")
                    
                    # Show matched strings
                    print(f"    Matched strings:")
                    for string in match.strings[:5]:
                        print(f"      - {string}")
                    
                    # Store matches
                    self.results['yara_matches'].append({
                        'rule': match.rule,
                        'meta': match.meta if hasattr(match, 'meta') else {},
                        'strings': [str(s) for s in match.strings]
                    })
            else:
                print("  No YARA matches found")
                
        except Exception as e:
            print(f"  YARA error: {e}")
            logger.debug(f"YARA error: {e}")

    def ml_classification(self):
        """Machine learning-based classification with feature extraction"""
        self.header("ML-BASED CLASSIFICATION")
        
        # Extract features for classification
        features = {
            'section_count': 0,
            'import_count': 0,
            'export_count': 0,
            'resource_count': 0,
            'average_entropy': 0.0,
            'suspicious_import_count': 0,
            'suspicious_characteristics': 0,
            'is_packed': False,
            'has_certificate': False,
            'has_tls': False,
            'anti_analysis_count': 0,
            'total_indicators': 0
        }
        
        # Collect features
        if self.pe:
            features['section_count'] = len(self.pe.sections)
            
            # Count imports
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                import_count = 0
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    import_count += len(entry.imports)
                features['import_count'] = import_count
            
            # Check for exports
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['export_count'] = len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols)
            
            # Check resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_count = 0
                for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for entry_type in entry.directory.entries:
                        resource_count += len(entry_type.directory.entries)
                features['resource_count'] = resource_count
            
            # Check certificates
            features['has_certificate'] = hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY')
            features['has_tls'] = hasattr(self.pe, 'DIRECTORY_ENTRY_TLS')
        
        # Calculate entropy features
        if self.results.get('sections'):
            entropies = [s['entropy'] for s in self.results['sections'] if 'entropy' in s]
            if entropies:
                features['average_entropy'] = sum(entropies) / len(entropies)
                features['is_packed'] = features['average_entropy'] > 7.0
        
        # Count suspicious imports
        if self.results.get('imports', {}).get('suspicious'):
            features['suspicious_import_count'] = sum(
                len(apis) for apis in self.results['imports']['suspicious'].values()
            )
        
        # Count anti-analysis techniques
        features['anti_analysis_count'] = len(self.results.get('anti_analysis', []))
        
        # Count total indicators
        features['total_indicators'] = len(self.results.get('indicators', []))
        
        # Calculate risk score based on features
        risk_score = 0
        
        # Packing increases risk
        if features['is_packed']:
            risk_score += 25
        
        # Suspicious imports
        if features['suspicious_import_count'] > 0:
            risk_score += min(30, features['suspicious_import_count'] * 3)
        
        # High entropy
        if features['average_entropy'] > 7.5:
            risk_score += 20
        
        # No certificate
        if not features['has_certificate']:
            risk_score += 10
        
        # Low import count (packing indicator)
        if features['import_count'] < 15:
            risk_score += 15
        
        # TLS callbacks (suspicious)
        if features['has_tls']:
            risk_score += 15
        
        # Anti-analysis techniques
        risk_score += min(20, features['anti_analysis_count'] * 3)
        
        # Indicators
        risk_score += min(30, features['total_indicators'] * 2)
        
        # Multiple MZ headers
        mz_count = len(re.findall(b'MZ', self.data))
        if mz_count > 5:
            risk_score += min(20, mz_count)
        
        risk_score = min(100, risk_score)
        
        # Classification
        classification = "LOW RISK"
        if risk_score >= 80:
            classification = "CRITICAL THREAT"
        elif risk_score >= 60:
            classification = "HIGH THREAT"
        elif risk_score >= 40:
            classification = "MEDIUM THREAT"
        elif risk_score >= 20:
            classification = "LOW THREAT"
        
        # Update results with consistent risk score
        self.results['risk_score'] = risk_score
        self.results['classification'] = classification
        
        # Display results
        print(f"  Risk Score: {risk_score}/100")
        print(f"  Classification: {classification}")
        print(f"\n  Feature Vector:")
        for key, value in features.items():
            print(f"    {key}: {value}")
        
        self.results['ml_classification'] = {
            'risk_score': risk_score,
            'classification': classification,
            'features': features
        }
        
        return risk_score, classification

    def comprehensive_report(self):
        """Generate comprehensive analysis report with consistent scoring"""
        print("\n" + "="*80)
        print("  COMPREHENSIVE ANALYSIS SUMMARY")
        print("="*80)
        
        # Get consistent risk score
        if self.results.get('ml_classification'):
            risk_score = self.results['ml_classification'].get('risk_score', 0)
            classification = self.results['ml_classification'].get('classification', 'Unknown')
        else:
            risk_score = self.results.get('risk_score', 0)
            classification = self.results.get('classification', 'Unknown')
        
        # Ensure results are updated
        self.results['risk_score'] = risk_score
        self.results['classification'] = classification
        
        print(f"\n  RISK ASSESSMENT:")
        print(f"    Risk Score: {risk_score}/100")
        print(f"    Classification: {classification}")
        
        # Indicators
        indicators = self.results.get('indicators', [])
        if indicators:
            print(f"\n  INDICATORS OF COMPROMISE:")
            for indicator in indicators[:10]:
                print(f"    - {indicator}")
            if len(indicators) > 10:
                print(f"    ... and {len(indicators)-10} more")
        else:
            print(f"\n  No obvious indicators of compromise found")
        
        # Behaviors
        behaviors = self.results.get('behaviors', [])
        if behaviors:
            print(f"\n  DETECTED BEHAVIORS:")
            for behavior in behaviors[:10]:
                if isinstance(behavior, dict):
                    print(f"    - {behavior.get('behavior')} (Confidence: {behavior.get('confidence', 0)*100:.0f}%)")
                else:
                    print(f"    - {behavior}")
        
        # Packer info
        if self.results.get('packer_info'):
            print(f"\n  PACKER INFORMATION:")
            for key, value in self.results['packer_info'].items():
                if isinstance(value, list):
                    print(f"    {key}: {', '.join(value[:3])}")
                    if len(value) > 3:
                        print(f"    ... and {len(value)-3} more")
                else:
                    print(f"    {key}: {value}")
        
        # YARA matches
        if self.results.get('yara_matches'):
            print(f"\n  YARA MATCHES:")
            for match in self.results['yara_matches'][:5]:
                print(f"    - {match.get('rule')}")
            if len(self.results['yara_matches']) > 5:
                print(f"    ... and {len(self.results['yara_matches'])-5} more")
        
        # Recommendations based on risk score
        print(f"\n  RECOMMENDATIONS:")
        if risk_score >= 80:
            print("    [CRITICAL] This file is highly suspicious. DO NOT execute.")
            print("    - Submit to sandbox for dynamic analysis")
            print("    - Extract and analyze any embedded resources")
            print("    - Monitor for network connections")
            print("    - Check for registry modifications")
            print("    - Consider memory forensics if executed")
        elif risk_score >= 60:
            print("    [HIGH] This file shows strong indicators of malware.")
            print("    - Execute only in isolated environment")
            print("    - Consider static analysis with IDA Pro")
            print("    - Analyze entry point behavior")
            print("    - Check for persistence mechanisms")
        elif risk_score >= 40:
            print("    [MEDIUM] Suspicious file with some indicators.")
            print("    - Run in sandbox to verify behavior")
            print("    - Check against antivirus scans")
            print("    - Monitor during execution")
            print("    - Review network activity if executed")
        elif risk_score >= 20:
            print("    [LOW] Some suspicious traits but likely safe.")
            print("    - Exercise caution during execution")
            print("    - Monitor system for anomalies")
            print("    - Verify with additional AV scans")
        else:
            print("    [SAFE] No significant threats detected.")
            print("    - File appears clean")
            print("    - Still exercise normal caution")
            print("    - Consider basic monitoring during execution")
        
        print(f"\n  ANALYSIS TIMESTAMP: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def run_analysis(self):
        """Run all analysis modules"""
        print("\n" + "="*80)
        print("  MALWARE ANALYZER PRO v3.1 - Advanced Threat Analysis")
        print("="*80)
        print(f"\n[*] Target: {self.filename}")
        print(f"[*] File Size: {self.filesize:,} bytes")
        print(f"[*] Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.quick_mode:
            print("\n  [QUICK MODE] - Running fast analysis only")
        
        try:
            # Run all analysis modules
            modules = [
                self.basic_info,
                self.pe_rich_header,
                self.debug_info_analysis,
                self.section_analysis,
                self.import_analysis,
                self.export_analysis,
                self.resource_analysis,
                self.tls_analysis,
                self.certificate_analysis,
                self.packer_detection,
                self.anti_debug_vm_detection,
                self.string_analysis,
                self.behavioral_analysis,
                self.advanced_entropy_analysis,
                self.ml_classification,
                self.yara_scan,
                self.disassembly_analysis,
                self.comprehensive_report
            ]
            
            if not self.quick_mode:
                # Run all modules
                for module in modules:
                    try:
                        module()
                    except Exception as e:
                        print(f"  [WARNING] Module {module.__name__} failed: {e}")
                        logger.warning(f"Module {module.__name__} failed: {e}")
            else:
                # Run only essential modules in quick mode
                quick_modules = [
                    self.basic_info,
                    self.section_analysis,
                    self.import_analysis,
                    self.packer_detection,
                    self.string_analysis,
                    self.ml_classification,
                    self.comprehensive_report
                ]
                for module in quick_modules:
                    try:
                        module()
                    except Exception as e:
                        print(f"  [WARNING] Module {module.__name__} failed: {e}")
            
        except Exception as e:
            print(f"\n[ERROR] Analysis error: {e}")
            logger.error(f"Analysis error: {e}", exc_info=True)

    def export_json(self, output_path: Optional[str] = None):
        """Export analysis results to JSON"""
        if not output_path:
            output_path = f"analysis_{self.filename}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Clean up results for JSON serialization
        json_results = {
            'file': {
                'name': self.filename,
                'size': self.filesize,
                'hashes': self.results.get('file_info', {}).get('hashes', {})
            },
            'analysis': {
                'risk_score': self.results.get('risk_score', 0),
                'classification': self.results.get('classification', 'Unknown'),
                'indicators': self.results.get('indicators', []),
                'behaviors': self.results.get('behaviors', []),
                'packer_info': self.results.get('packer_info', {}),
                'yara_matches': self.results.get('yara_matches', []),
                'anti_analysis': self.results.get('anti_analysis', []),
                'timestamp': datetime.datetime.now().isoformat()
            },
            'details': {
                'sections': self.results.get('sections', []),
                'imports': self.results.get('imports', {}),
                'exports': self.results.get('exports', []),
                'resources': self.results.get('resources', []),
                'tls_callbacks': self.results.get('tls_callbacks', []),
                'certificates': self.results.get('certificates', {}),
                'entropy_analysis': self.results.get('entropy_analysis', {})
            }
        }
        
        # Write JSON
        with open(output_path, 'w') as f:
            json.dump(json_results, f, indent=2, default=str)
        
        print(f"\n  JSON report saved to: {output_path}")
        return output_path

def main():
    """Main entry point with command line arguments"""
    parser = argparse.ArgumentParser(
        description='Malware Analyzer Pro v3.1 - Advanced PE Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer_pro.py suspicious.exe
  python analyzer_pro.py malware.exe --quick
  python analyzer_pro.py sample.exe --yara-rules ./rules --export-json
  python analyzer_pro.py test.exe --output-dir ./reports
        """
    )
    
    parser.add_argument('file', help='PE file to analyze')
    parser.add_argument('--quick', action='store_true', help='Run quick analysis (skip resource-heavy modules)')
    parser.add_argument('--export-json', metavar='PATH', help='Export results to JSON file')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--yara-rules', default='yara_rules', help='Directory containing YARA rules')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--disable-logging', action='store_true', help='Disable file logging')
    
    args = parser.parse_args()
    
    # Setup output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped log file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = output_dir / f"analysis_{Path(args.file).stem}_{timestamp}.txt"
    
    # Setup dual output (console + file)
    class Tee:
        def __init__(self, file_path):
            self.terminal = sys.stdout
            self.log = open(file_path, 'w', encoding='utf-8') if not args.disable_logging else None
        
        def write(self, msg):
            self.terminal.write(msg)
            if self.log:
                self.log.write(msg)
        
        def flush(self):
            self.terminal.flush()
            if self.log:
                self.log.flush()
        
        def __del__(self):
            if self.log:
                self.log.close()
    
    # Redirect stdout
    sys.stdout = Tee(log_file)
    
    try:
        # Configure analyzer
        config = {
            'quick_mode': args.quick,
            'verbose': args.verbose,
            'yara_rules_dir': args.yara_rules,
            'output_dir': args.output_dir
        }
        
        # Create analyzer instance
        analyzer = MalwareAnalyzerPro(args.file, config)
        
        # Run analysis
        analyzer.run_analysis()
        
        # Export JSON if requested
        if args.export_json:
            if args.export_json == 'PATH':
                json_path = output_dir / f"analysis_{Path(args.file).stem}_{timestamp}.json"
                analyzer.export_json(str(json_path))
            else:
                analyzer.export_json(args.export_json)
        
        print(f"\n{'='*80}")
        print(f"  Analysis complete! Report saved to: {log_file}")
        print(f"{'='*80}\n")
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Restore stdout
        if hasattr(sys.stdout, 'log') and sys.stdout.log:
            sys.stdout.log.close()
        if hasattr(sys.stdout, 'terminal'):
            sys.stdout = sys.stdout.terminal

if __name__ == '__main__':
    main()
