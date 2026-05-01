import os

def get_ip():
    return os.environ.get('IP')

def get_scan_type():
    return os.environ.get('SCAN_TYPE')

def get_fname():
    return os.environ.get('FNAME')

def is_service_scan_enabled():
    return os.environ.get('SERVICE_SCAN', 'true').lower() == 'true'

def is_host_check_enabled():
    return os.environ.get('HOST_CHECK', 'true').lower() == 'true'

def get_nmap_path():
    return os.environ.get('NMAP_PATH', 'nmap')

def get_is_debug_enabled():
    return os.environ.get('DEBUG', 'false').lower() == 'true'

# Zombie related
def get_is_zombie():
    return os.environ.get('ZOMBIE') == 'enabled'

def get_zombie_username():
    return os.environ.get('USERNAME')

def get_zombie_password():
    return os.environ.get('PASSWORD')

def get_zombie_ip():
    return os.environ.get('ZOMBIE_IP')

def is_auto_update_enabled():
    return os.environ.get('AUTO_UPDATE_CHECK', 'true').lower() == 'true'