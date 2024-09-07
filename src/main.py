import argparse
import time
import sys
import hashlib
import os

# 파일 시그니처 정의
FILE_SIGNATURES = {
    
    'pdf': b'%PDF',
    'gif': [b'GIF87a', b'GIF89a'],
    'png': b'\x89PNG\r\n\x1a\n',
    'jpg': [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe8', b'\xff\xd8\xff\xdb', b'\xff\xd8\xff\xee'],
    'zip': b'PK\x03\x04',
    'exe': b'MZ',
    'msi': b'MZ',  
    'ico': b'\x00\x00\x01\x00',
    'cur': b'\x00\x00\x02\x00',
    'mpg': b'\x00\x00\x01\xb3',
    'doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', b'\xec\xa5\xc1\x00', b'\xbe\x00\x00\x00\xab\x00\x00\x00'],
    'xls': [b'\xfd\xff\xff\xff', b'\xfe\xff'],
    'ppt': [b'\x00\x6e\x1e\xf0', b'\xfd\xff\xff\xff'],
    'mp4': b'\x00\x00\x00\x18ftyp',
    'mov': b'moov',
    'bmp': b'BM',
    'tar': b'ustar',
    'gz': [b'\x1f\x8b\x08', b'\x1f\x9d', b'\x1f\xa0'],
    'avi': b'RIFF',
    'wav': b'RIFF',
    'mp3': [b'ID3', b'\xff\xfb'],
    'psd': b'8BPS',
    'rtf': b'{\\rtf',
    'xml': b'<?xml',
    'json': b'{',
    'flv': b'FLV',
    'rm': b'.RMF',
    'tif': [b'II*\x00', b'MM\x00*'],
    'arj': b'\x60\xea',
    'rar': b'Rar!',
    '3gp': [b'\x00\x00\x00\x14ftyp3gp', b'\x00\x00\x00\x20ftyp3g2'],
    'aac': b'ADIF',
    'amr': b'#!AMR',
    'iso': b'CD001',
    'lha': [b'\x2D\x6C\x68', b'\x2D\x6C\x68\x35'],
    'eps': b'%!PS-Adobe',
    'fli': [b'\xAF\x11', b'\x01\x11\xAF'],
    'qxd': [b'\x00\x00\x49\x49\x58\x50\x52', b'\x00\x00\x4D\x4D\x58\x50\x52'],
    'ai': b'%!PS-Adobe',
    'wma': b'0&\xb2u',
    'wmv': b'0&\xb2u',
    'asf': b'0&\xb2u',
    '7z': b'7z\xbc\xaf\x27\x1c',
    'bz2': b'BZh',
    'cab': b'MSCF',
    'dmg': b'x',
    'jar': b'PK\x03\x04',
    'gzip': b'\x1F\x8B',
    'arc': b'\x1A',
    'jpeg': [b'\xFF\xD8\xFF\xDB', b'\xFF\xD8\xFF\xEE', b'\xFF\xD8\xFF\xE1'],
    'pif': b'\x00',
    'mac': b'\x00\x00\x00\x02',
    'wmf': b'\xd7\xcd\xc6\x9a',
    'mp2': b'\xff\xf3',
    'dbf': [b'\x02', b'\x03'],
    'db': b'\x00\x01',
    'mdb': b'\x00\x01\x00\x00Standard Jet DB',
    'emf': b'\x01\x00\x00\x00',
    'docx': b'PK\x03\x04',
    'pptx': b'PK\x03\x04',
    'xlsx': b'PK\x03\x04',

}

# 랜섬웨어와 관련된 확장자 목록
RANSOMWARE_EXTENSIONS = [

    'locky', 'zepto', 'odin', 'cerber', 'crysis', 'wallet', 'zzzzz', 'zepto', 'ccc', 'exx', 'ecc', 'crypt', 'crab', 'cbf',
    'arena', 'dharma', 'wallet', 'arrow', 'grt', 'ryuk', 'phobos', 'krab', 'fucked', 'crypted', 'crypted', 'satan', 'xrat',
    'gandcrab', 'cyborg', 'salus', 'ciphered', 'shiva', 'stupid', 'why', 'weapologize', 'grandcrab', 'megacortex', 'revil',
    'ekvf', 'fairytail', 'exorcist', 'mamba', 'killing_time', 'recovery', 'volcano', 'pscrypt', 'tcps', 'fuxsocy', 'heof',
    'matrix', 'medusa', 'snake', 'ftcode', 'calipso', 'encrypted', 'vault', 'shariz', 'tor', 'globeimposter', 'kogda',
    'crypmic', 'bokbot', 'dewar', 'defray', 'greystar', 'pclock', 'moisha', 'zcrypt', 'djvu', 'dotmap', 'sodinokibi',
    'calipto', 'fun', 'worm', 'inferno', 'medy', 'fudcrypt', 'zohar', 'nig', 'ogre', 'uizsdgpo', 'hermes', 'nellyson',
    'pay', 'bepow', 'futc', 'suck', 'f**ked', 'foxf***r', 'hotjob', 'gusar', 'jigsaw', 'oklah', 'lockfile', 'aesc', 'wb',
    'tycoon', 'careto', 'snake', 'azov', 'conti', 'ragnarok', 'shiva', 'crippled', 'trosy', 'johnny', 'regen', 'whatthe',
    '000', 'hitler', 'somethinghere', 'uw', 'anubi', 'notgotenough', 'justforyou', 'bondy', 'ark', 'kubos', 'police',
    'aprilfool', 'bitch', 'crisis', 'teerac', 'long', 'infom', 'woswos', 'uw4w', 'ctrb', 'purge', 'fiwlgphz', 'platano',
    'pro', 'locked', 'eyy', 'whythis', 'k0der', 'joker', 'grt', 'fucku', 'charm', 'conti', 'doubleup', 'payup', 'firecrypt',
    'miyake', 'senpai', 'onspeed', 'fxckoff', 'stupid', 'zer0', 'p0rn', 'beethoven', 'im sorry', 'kuba', 'hahaha', '555',
    'sexx', 'fuckyou', 'supercrypt', 'gudrotka', 'catchmeifyoucan', 'bambam', 'lucy', 'sadism', 'fedup', 'makop', 'alpha',
    'master', 'mcafee', 'bastard', 'locki', 'striker', 'grimly', 'cryptolocker', 'zcrypt', 'kukaracha', 'kraken', 'supersystem',
    'hot', 'ispy', 'newversion', 'payfast', 'futurat', 'unlock', 'kkk', 'openme', 'blablabla', 'goof', 'psycho', 'trigger',
    'memeware', 'emotet', 'wannacry', 'notpetya'

]

def print_ascii_art():

    ascii_art = """

    █████╗ ███╗   ██╗████████╗██╗    ███████╗██╗ ██████╗ ███╗   ██╗ █████╗ ████████╗██╗   ██╗██████╗ ███████╗
    ██╔══██╗████╗  ██║╚══██╔══╝██║    ██╔════╝██║██╔════╝ ████╗  ██║██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██╔════╝
    ███████║██╔██╗ ██║   ██║   ██║    ███████╗██║██║  ███╗██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝█████╗  
    ██╔══██║██║╚██╗██║   ██║   ██║    ╚════██║██║██║   ██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗██╔══╝  
    ██║  ██║██║ ╚████║   ██║   ██║    ███████║██║╚██████╔╝██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║███████╗
    ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝    ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
    
    """
    
    print(ascii_art)

def show_loading_effect():  # 로딩 효과 출력

    for _ in range(10):

        sys.stdout.write(". ")    
        sys.stdout.flush()
        
        time.sleep(0.5)
    
    print()

def calculate_file_hash(file_path, hash_algorithm='sha256'):    # 파일 해시 계산
    
    hash_func = hashlib.new(hash_algorithm)
    
    try:
    
        with open(file_path, 'rb') as f:
    
            while chunk := f.read(8192):
    
                hash_func.update(chunk)
    
    except FileNotFoundError:
    
        print(f"Error: {file_path} 파일을 찾을 수 없습니다.")
    
        return None

    return hash_func.hexdigest()

def check_file_integrity(file_path, expected_hash=None):
    
    try:
    
        with open(file_path, 'rb') as f:
    
            file_signature = f.read(20)
    
    except FileNotFoundError:
    
        print(f"Error: {file_path} 파일을 찾을 수 없습니다.")
    
        return
    
    # 파일 확장자 추출
    file_extension = file_path.split('.')[-1].lower()

    # 랜섬웨어 관련 확장자 확인
    is_ransomware_extension = file_extension in RANSOMWARE_EXTENSIONS

    # 파일 시그니처와 확장자 비교
    suspicious = False
    
    if file_extension in FILE_SIGNATURES:
        
        expected_signatures = FILE_SIGNATURES[file_extension]
        
        if not isinstance(expected_signatures, list):
        
            expected_signatures = [expected_signatures]
        
        if any(file_signature.startswith(sig) for sig in expected_signatures):
        
            print(f"{file_path}의 파일 시그니처가 정상입니다. 파일 형식: {file_extension.upper()}")
        
        else:
        
            print(f"경고: {file_path}의 파일 시그니처가 예상과 다릅니다. 파일 형식: {file_extension.upper()}")
        
            suspicious = True
    
    else:
        
        print(f"알 수 없는 확장자입니다: {file_extension}")
        
        suspicious = True

    # 파일이 손상되거나 암호화된 것으로 의심되는 경우
    if suspicious:
        
        if is_ransomware_extension:
        
            print(f"경고: {file_path}의 파일이 암호화되었거나 손상된 것으로 보입니다. 랜섬웨어에 감염된 파일입니다.")
        
        else:
        
            print(f"경고: {file_path}의 파일이 암호화되었거나 손상된 것으로 보입니다. 랜섬웨어 감염 의심 파일입니다.")

    # 해시 무결성 검사 수행
    if expected_hash:
        
        calculated_hash = calculate_file_hash(file_path)
        
        if calculated_hash and calculated_hash != expected_hash:
        
            print(f"경고: {file_path}의 파일 해시 무결성이 훼손되었습니다.")
        
        elif calculated_hash:
        
            print(f"{file_path}의 파일 해시가 무결합니다.")

def check_for_ransomware(file_path):    # 파일 이름 패턴 분석
    
    file_name = file_path.split('/')[-1].lower()
    
    suspicious = False
    
    # 랜섬웨어 의심 확장자
    if any(ext in file_name for ext in RANSOMWARE_EXTENSIONS):
        
        print(f"경고: {file_path}는 랜섬웨어와 관련된 확장자를 포함하고 있습니다.")
        
        suspicious = True
    
    # 랜섬웨어 의심 이름 패턴
    if "readme" in file_name or "decrypt" in file_name:
        
        print(f"경고: {file_path}는 랜섬웨어 관련 파일일 수 있습니다 (이름 패턴 감지됨).")
        
        suspicious = True
    
    if not suspicious:
        
        print(f"{file_path}는 랜섬웨어에 감염되지 않은 정상 파일입니다.")
        
def apply_anti_debugging_and_obfuscation(file_path):
    
    if not os.path.exists(file_path):
    
        print(f"Error: {file_path} 파일을 찾을 수 없습니다.")
    
        return
    print(f"{file_path}에 안티디버깅 및 난독화 기법을 적용 중입니다...")
    
    anti_debugging_code = b"\xEB\xFE"  # 무한 루프 삽입
    
    with open(file_path, 'ab') as f:
    
        f.write(anti_debugging_code)
    
    with open(file_path, 'ab') as f:
    
        random_bytes = os.urandom(10)
    
        f.write(random_bytes)
    
    print("안티디버깅 및 난독화 기법이 성공적으로 적용되었습니다.")

def detect_anti_debugging_and_obfuscation(file_path):
    
    if not os.path.exists(file_path):
    
        print(f"Error: {file_path} 파일을 찾을 수 없습니다.")
    
        return
    
    print(f"{file_path}에 안티디버깅 및 난독화가 적용되었는지 확인 중입니다...")
    
    with open(file_path, 'rb') as f:
    
        content = f.read()
    
        if b"\xEB\xFE" in content:
    
            print(f"{file_path}에 안티디버깅 기법이 적용되었습니다.")
    
        else:
    
            print(f"{file_path}에 안티디버깅 기법이 적용되지 않았습니다.")
            
def remove_anti_debugging_and_obfuscation(file_path):   # 안티디버깅 기법과 난독화 기법을 해제하는 함수
    
    if not os.path.exists(file_path):
    
        print(f"Error: {file_path} 파일을 찾을 수 없습니다.")
    
        return

    print(f"{file_path}에서 안티디버깅 및 난독화 기법을 제거하는 중입니다...")

    # 파일에서 안티디버깅 코드 및 난독화된 바이트 패턴을 찾고 제거
    with open(file_path, 'rb') as f:
    
        content = f.read()

    # 안티디버깅 코드 제거
    content = content.replace(b"\xEB\xFE", b"")

    # 파일을 덮어쓰기 모드로 열고 변경된 내용을 기록
    with open(file_path, 'wb') as f:
    
        f.write(content)

    print("안티디버깅 및 난독화 기법이 성공적으로 제거되었습니다.")

def main():
    
    print_ascii_art()
    
    show_loading_effect()
    
    parser = argparse.ArgumentParser(description="Anti Signature 프로그램: 파일 무결성 검사 도구 및 랜섬웨어 감염 여부 확인")
    
    parser.add_argument(
    
        '-f', '--file', 
        type=str, 
        help='무결성을 검사할 파일 경로를 지정하고, 선택적으로 파일 해시 값을 제공할 수 있습니다. 예: -f example.pdf:d41d8cd98f00b204e9800998ecf8427e'
    
    )
    
    parser.add_argument(
    
        '-R', '--ransomware', 
        action='store_true', 
        help='파일의 랜섬웨어 감염 여부를 확인합니다.'
    
    )
    
    parser.add_argument(
        
        '-D', '--apply-debug', 
        action='store_true', 
        help='PE 또는 ELF 파일에 안티디버깅 및 난독화 기법을 적용합니다.'
    
    )
    
    parser.add_argument(
        
        '-dd', '--detect-debug', 
        action='store_true', 
        help='PE 또는 ELF 파일에 안티디버깅 및 난독화 기법이 적용되었는지 확인합니다.'
    
    )
    
    parser.add_argument(
        '-dx', '--remove-debug', 
        action='store_true', 
        help='PE 또는 ELF 파일에서 안티디버깅 및 난독화 기법을 제거합니다.'
    )
    
    args = parser.parse_args()

    # 파일 경로와 해시 분리
    if args.file:
        
        file_info = args.file.split(':')
        
        file_path = file_info[0]
        
        expected_hash = file_info[1] if len(file_info) > 1 else None

        check_file_integrity(file_path, expected_hash)
        
        if args.ransomware:
        
            check_for_ransomware(file_path)
            
        if args.apply_debug:
            
            apply_anti_debugging_and_obfuscation(file_path)
        
        if args.detect_debug:
            
            detect_anti_debugging_and_obfuscation(file_path)
            
        if args.remove_debug:
            
            remove_anti_debugging_and_obfuscation(file_path)
    
    else:

        parser.print_help()

if __name__ == "__main__":

    main()
