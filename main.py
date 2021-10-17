#!/usr/bin/env python3

from sys import argv, exit
import psutil


def is_process_running(process_name):
    for proc in psutil.process_iter():
        try:
            if process_name.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False


def get_pid(process):
    process_dict = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
            if process.lower() in pinfo['name'].lower():
                process_dict.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return process_dict


def read_heap(pid):
    try:
        maps_file = open("/proc/{}/maps".format(pid), 'r')
    except IOError as e:
        print("Can't open file /proc/{}/maps: IOError: {}".format(pid, e))
        exit(1)

    heap_info = None
    for line in maps_file:
        if 'heap' in line:
                heap_info = line.split()
    maps_file.close()
    if 'heap' == None:
        print('No heap found!')
        exit(1)
    addr = heap_info[0].split('-')
    perms = heap_info[1]
    if 'r' not in perms or 'w' not in perms:
        print('Heap does not have read and/or write permission')
        exit(0)
    try:
        mem_file = open("/proc/{}/mem".format(pid), 'rb+')
    except IOError as e:
        print("Can't open file /proc/{}/maps: IOError: {}".format(pid, e))
        exit(1)
    heap_start = int(addr[0], 16)
    heap_end = int(addr[1], 16)
    #heap_start = 0x03820000
    #heap_end = 0x03824000
    mem_file.seek(heap_start)

    #offset = int("0x205",16)
    #heap_startOffset = heap_start + offset
    #heap = mem_file.read(heap_startOffset - heap_start)
    heap = mem_file.read(heap_end - heap_start)

    f = open("data.txt", "a")
    #f.write(heap.decode("ASCII", 'ignore'))
    f.write(heap.decode("utf-8", 'ignore'))
    f.close()

    search_string = "normal"
    #print(bytes(charname, "ASCII"))

    #str_offset = heap.find(bytes(search_string, "ASCII"))
    #if str_offset < 0:
    #    print("Can't find {} in /proc/{}/mem".format(search_string, pid))
    #    exit(1)
    #mem_file.seek(heap_start + str_offset)

    try:
        str_offset = heap.index(bytes(search_string, "ASCII"))
    except Exception:
        print("Can't find '{}'".format(search_string))
        mem_file.close()
        exit(0)
    print("[*] Found '{}' at {:x}".format(search_string, str_offset))

    #print(heap_start)
    #print(offset)
    #print(heap_startOffset)
    #print("Dumping heap range: ")
    #print(heap.decode('ISO-8859-1'))
    #print(heap.decode('windows-1252',errors='ignore'))
    #print(heap.decode('utf-16-le', errors='ignore'))
    #print(heap.decode('ascii', errors='ignore'))
    #print(heap.decode('utf-8', 'ignore'))


if is_process_running("D2R") == True:
    print("Process is running, starting pid fetch.")
    dict = get_pid("D2R")
    pid = dict[0]['pid']
    print("Process ID: ", pid)
    read_heap(pid)
else:
    print("False, process not running.")
    exit(0)