#!/usr/bin/env python3

import sys
import os
import hashlib
import re
import math
import datetime
from pathlib import Path

# Try to import pefile for PE file parsing
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("[!] Installing pefile...")
    os.system(f"{sys.executable} -m pip install pefile")
    import pefile
    PEFILE_AVAILABLE = True

# Try to import capstone for disassembly capabilities
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("[!] Capstone not available - disassembly disabled")

class MalwareAnalyzer:
    """Main analyzer class that processes PE files and extracts security-relevant information"""
    
    def __init__(self, filepath):
        """Initialize the analyzer with a file path and load the file data"""
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Read the entire file into memory for analysis
        with open(filepath, 'rb') as f:
            self.data = f.read()
        
        self.filename = self.filepath.name
        self.filesize = len(self.data)
        self.pe = None
        
        # Try to parse as PE file if it has the MZ header
        if self.data[:2] == b'MZ':
            try:
                self.pe = pefile.PE(data=self.data)
            except Exception as e:
                print(f"[!] PE parse error: {e}")
    
    def header(self, title):
        """Print a formatted section header for better readability"""
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}")
    
    def basic_info(self):
        """Display fundamental file information including hashes and PE headers"""
        self.header("BASIC FILE INFORMATION")
        print(f"  Filename:          {self.filename}")
        print(f"  File Size:         {self.filesize:,} bytes ({self.filesize/1024:.1f} KB)")
        print(f"  MD5:              {hashlib.md5(self.data).hexdigest()}")
        print(f"  SHA1:             {hashlib.sha1(self.data).hexdigest()}")
        print(f"  SHA256:           {hashlib.sha256(self.data).hexdigest()}")
        
        # Display PE-specific information if available
        if self.data[:2] == b'MZ':
            print(f"  Type:              PE Executable")
            if self.pe:
                print(f"  Machine:           {hex(self.pe.FILE_HEADER.Machine)}")
                print(f"  Compiled:          {self.pe.FILE_HEADER.TimeDateStamp}")
                print(f"  Entry Point RVA:   {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
                print(f"  Image Base:        {hex(self.pe.OPTIONAL_HEADER.ImageBase)}")
                print(f"  Entry Point VA:    {hex(self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
                print(f"  Sections:          {len(self.pe.sections)}")
                arch = "x64" if self.pe.FILE_HEADER.Machine == 0x8664 else "x86"
                print(f"  Architecture:      {arch}")
    
    def section_analysis(self):
        """Analyze PE sections for suspicious characteristics like high entropy or WX permissions"""
        if not self.pe:
            return
        
        self.header("SECTION ANALYSIS")
        print(f"  {'Name':<10} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<8} {'Perms':<8} {'Flags'}")
        print(f"  {'-'*65}")
        
        for section in self.pe.sections:
            try:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                virt_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                
                # Calculate entropy to detect packed/encrypted sections
                section_data = section.get_data()
                entropy = self._entropy(section_data) if section_data else 0.0
                
                # Determine section permissions
                perms = []
                if section.Characteristics & 0x20000000: perms.append("X")
                if section.Characteristics & 0x40000000: perms.append("R")
                if section.Characteristics & 0x80000000: perms.append("W")
                perm_str = ''.join(perms) if perms else "NONE"
                
                # Flag suspicious characteristics
                flags = ""
                if entropy > 7.0:
                    flags += "[HIGH ENTROPY] "
                if 'W' in perm_str and 'X' in perm_str:
                    flags += "[WX - SUSPICIOUS] "
                
                print(f"  {name:<10} {virt_size:<10} {raw_size:<10} {entropy:<8.3f} {perm_str:<8} {flags}")
            except:
                pass
    
    def _entropy(self, data):
        """Calculate Shannon entropy of data to detect encryption or packing"""
        if not data: return 0.0
        entropy = 0
        for x in range(256):
            p = data.count(x) / len(data)
            if p > 0: entropy += -p * math.log2(p)
        return entropy
    
    def string_analysis(self, min_length=4):
        """Extract and analyze human-readable strings from the binary"""
        self.header("STRING ANALYSIS (Top 30 Interesting)")
        
        # Find ASCII strings
        strings = set()
        for match in re.finditer(b'[\x20-\x7e]{%d,}' % min_length, self.data):
            try:
                s = match.group().decode('ascii', errors='ignore')
                if s.strip(): strings.add(s)
            except: pass
        
        # Find Unicode strings
        for match in re.finditer(b'(?:[\x20-\x7e]\x00){%d,}' % min_length, self.data):
            try:
                s = match.group().decode('utf-16-le', errors='ignore')
                if s.strip(): strings.add(s)
            except: pass
        
        # Patterns that might indicate malicious intent
        patterns = {
            r'http[s]?://': 'URL', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}': 'IP',
            r'SOFTWARE\\Microsoft\\Windows': 'Registry', r'cmd\.exe|powershell\.exe': 'Shell',
            r'CreateFile|WriteFile|ReadFile': 'FileAPI', r'VirtualAlloc|VirtualProtect': 'MemAPI',
            r'CreateThread|CreateProcess|CreateRemoteThread': 'ProcAPI',
            r'\.exe|\.dll|\.sys': 'Binary', r'password|passwd|secret|key': 'Creds',
            r'mutex|Global\\': 'Mutex', r'GetAsyncKeyState|SetWindowsHookEx': 'Keylog',
        }
        
        # Score strings based on suspicious patterns
        scored = []
        for s in strings:
            score = 0
            cats = set()
            for pattern, cat in patterns.items():
                if re.search(pattern, s, re.IGNORECASE):
                    score += 1
                    cats.add(cat)
            if score > 0 and len(s) <= 200:
                scored.append((s, score, cats))
        
        # Display top suspicious strings
        scored.sort(key=lambda x: x[1], reverse=True)
        
        if scored:
            for i, (s, score, cats) in enumerate(scored[:30], 1):
                print(f"  {i:2}. [{', '.join(sorted(cats))}]")
                print(f"      {s[:150]}")
                print()
    
    def import_analysis(self):
        """Analyze imported functions for potentially malicious API calls"""
        if not self.pe:
            return
        
        self.header("IMPORT ANALYSIS")
        
        # Define suspicious API patterns by category
        suspicious = {
            'Process Injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
            'Anti-Debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetTickCount'],
            'Network': ['URLDownloadToFile', 'WinHttpOpen', 'InternetConnect', 'socket', 'connect', 'send'],
            'Persistence': ['RegCreateKey', 'RegSetValueEx', 'CreateService', 'OpenSCManager'],
            'File Ops': ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile'],
            'Keylogging': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState'],
        }
        
        found = {}
        total = 0
        
        # Parse import table
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            total += 1
                            api = imp.name.decode('utf-8', errors='ignore')
                            for cat, apis in suspicious.items():
                                if api in apis:
                                    if cat not in found: found[cat] = []
                                    found[cat].append(f"{dll}!{api}")
                except: pass
        
        print(f"  Total imports: {total}")
        if found:
            for cat, apis in found.items():
                print(f"\n  [{cat}] ({len(apis)} found)")
                for api in apis[:10]:
                    print(f"    - {api}")
        else:
            print("\n  No suspicious imports found")
    
    def disasm_entry(self, count=30):
        """Disassemble the entry point to understand initial execution behavior"""
        if not CAPSTONE_AVAILABLE or not self.pe:
            return
        
        self.header(f"DISASSEMBLY AT ENTRY POINT ({count} instructions)")
        
        try:
            entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_offset = self.pe.get_offset_from_rva(entry_rva)
            
            # Set up disassembler based on architecture
            if self.pe.FILE_HEADER.Machine == 0x014c:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif self.pe.FILE_HEADER.Machine == 0x8664:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                return
            
            # Disassemble entry point code
            code = self.data[entry_offset:entry_offset + count * 20]
            icount = 0
            
            for addr, size, mnemonic, op_str in md.disasm_lite(code, entry_offset):
                if icount >= count: break
                hex_bytes = ' '.join(f'{b:02x}' for b in self.data[addr:addr+size])
                va = self.pe.OPTIONAL_HEADER.ImageBase + addr
                # Add comments for interesting instructions
                comment = ""
                if mnemonic in ['call', 'jmp'] and '[' in op_str: comment = " ; [indirect]"
                elif mnemonic in ['int', 'syscall']: comment = " ; [syscall]"
                elif mnemonic == 'cpuid': comment = " ; [VM check?]"
                print(f"  {hex(va)} | {hex_bytes:<24} | {mnemonic:<8} {op_str:<20}{comment}")
                icount += 1
        except Exception as e:
            print(f"  Disasm error: {e}")
    
    def malware_indicators(self):
        """Collect and score various indicators of compromise"""
        self.header("MALWARE INDICATORS")
        
        indicators = []
        risk = 0
        
        # Check for multiple MZ headers (possible file binder)
        mz_count = len(re.findall(b'MZ', self.data))
        if mz_count > 1:
            indicators.append(f"[CRITICAL] Multiple MZ headers ({mz_count}) - possible binder/dropper")
            risk += 30
        
        # Check for WX (Writable + Executable) sections
        if self.pe:
            for section in self.pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if section.Characteristics & 0x80000000 and section.Characteristics & 0x20000000:
                        indicators.append(f"[CRITICAL] WX section: {name}")
                        risk += 25
                except: pass
        
        # Detect common packers
        packers = {'.upx': 'UPX', '.aspack': 'ASPack', '.mpress': 'MPRESS', '.vmp': 'VMProtect'}
        if self.pe:
            for section in self.pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                    if name in packers:
                        indicators.append(f"[MEDIUM] Packer: {packers[name]}")
                        risk += 10
                except: pass
        
        # Flag sections with abnormally high entropy
        if self.pe:
            for section in self.pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    data = section.get_data()
                    if data:
                        entropy = self._entropy(data)
                        if entropy > 7.5:
                            indicators.append(f"[HIGH] High entropy in {name}: {entropy:.2f}")
                            risk += 15
                except: pass
        
        # Check for anti-analysis strings
        for s in [b'vbox', b'vmware', b'qemu', b'sandboxie', b'ollydbg', b'ida']:
            if s in self.data.lower():
                indicators.append(f"[INFO] Anti-analysis: {s.decode()}")
                risk += 3
        
        # Detect common malware techniques through import analysis
        if self.pe and hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = set()
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    for imp in entry.imports:
                        if imp.name: imports.add(imp.name.decode('utf-8', errors='ignore'))
                except: pass
            
            # Process injection capability
            if 'VirtualAllocEx' in imports and 'WriteProcessMemory' in imports:
                indicators.append("[HIGH] Process injection capability")
                risk += 20
            # Download and execute capability
            if 'URLDownloadToFile' in imports and 'CreateProcess' in imports:
                indicators.append("[CRITICAL] Download & Execute")
                risk += 25
        
        # Display findings and calculate risk score
        if indicators:
            for i in sorted(indicators, reverse=True):
                print(f"  {i}")
        else:
            print("  No obvious indicators (sophisticated malware may evade)")
        
        risk = min(risk, 100)
        print(f"\n  {'-'*50}")
        print(f"  RISK SCORE: {risk}/100")
        
        # Interpret the risk score
        if risk >= 70: print("  [!!!] CRITICAL - Highly likely malicious!")
        elif risk >= 40: print("  [!!] HIGH RISK - Suspicious file")
        elif risk >= 20: print("  [!] MEDIUM RISK - Some suspicious traits")
        else: print("  [i] LOW RISK - But always verify in sandbox")
    
    def save_report(self):
        """Generate a filename for saving analysis results"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        
        report_name = report_dir / f"analysis_{self.filename}_{timestamp}.txt"
        return report_name


def main():
    """Main entry point - orchestrates the analysis process"""
    if len(sys.argv) != 2:
        print("Usage: python analyzer_v2.py <file.exe>")
        print("Example: python analyzer_v2.py srs.exe")
        sys.exit(1)
    
    filepath = sys.argv[1]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    filename = Path(filepath).stem
    report_file = reports_dir / f"analysis_{filename}_{timestamp}.txt"
    
    # Set up dual output to screen and file
    class Tee:
        def __init__(self, file_path):
            self.terminal = sys.stdout
            self.log = open(file_path, 'w', encoding='utf-8')
        def write(self, msg):
            self.terminal.write(msg)
            self.log.write(msg)
        def flush(self):
            self.terminal.flush()
            self.log.flush()
    
    sys.stdout = Tee(report_file)
    
    try:
        # Begin analysis with header
        print("="*70)
        print("  MALWARE ANALYZER v2 - Auto-Save Enabled")
        print("="*70)
        print(f"\n[*] Target: {filepath}")
        print(f"[*] Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Report: {report_file}\n")
        
        # Run all analysis modules
        analyzer = MalwareAnalyzer(filepath)
        analyzer.basic_info()
        analyzer.section_analysis()
        analyzer.import_analysis()
        analyzer.string_analysis()
        analyzer.disasm_entry(30)
        analyzer.malware_indicators()
        
        print(f"\n{'='*70}")
        print(f"  Analysis Complete!")
        print(f"{'='*70}\n")
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
    finally:
        # Clean up and save report
        sys.stdout.log.close()
        sys.stdout = sys.stdout.terminal
        print(f"\n[✓] Report saved to: {report_file}")
        print(f"[✓] Open with: notepad {report_file}")

if __name__ == '__main__':
    main()
