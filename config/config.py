#!/usr/bin/python3
"""
PINGuin - Configuration Module
Global configuration variables and accessor functions
"""

IP = None
SCAN_TYPE = None
FNAME = None

def set_ip_address(ip):
    """Set target IP address"""
    global IP
    IP = ip

def get_ip():
    """Get target IP address"""
    return IP

def set_scan_type(scan_type):
    """Set scan type (stealthy/aggressive)"""
    global SCAN_TYPE
    SCAN_TYPE = scan_type

def get_scan_type():
    """Get current scan type"""
    return SCAN_TYPE

def set_fname(fname):
    """Set results folder name"""
    global FNAME
    FNAME = fname

def get_fname():
    """Get results folder name"""
    return FNAME

def set_is_zombie(zombie):
    """Set if zombie mode is enabled"""
    global ZOMBIE
    ZOMBIE = zombie

def get_is_zombie():
    """Get if zombie mode is enabled"""
    return ZOMBIE

def set_zombie_username(username):
    """Set username"""
    global USERNAME
    USERNAME = username

def get_zombie_username():
    """Get username"""
    return USERNAME

def set_zombie_password(password):
    """Set password"""
    global PASSWORD
    PASSWORD = password

def get_zombie_password():
    """Get password"""
    return PASSWORD

def set_zombie_ip(ip):
    """Set zombie IP"""
    global ZOMBIE_IP
    ZOMBIE_IP = ip

def get_zombie_ip():
    """Get zombie IP"""
    return ZOMBIE_IP