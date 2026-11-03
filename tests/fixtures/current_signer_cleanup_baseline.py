"""Original cleanup implementation retained only for differential unit evidence."""
def _cleanup_owned_tree(root: Path, allowed_subdirs: set[str]) -> bool:
    if not root.exists():
        return True
    try:
        info = os.lstat(root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            return False
        entries = set(os.listdir(root))
        if not entries <= allowed_subdirs:
            return False
        for sub_name in sorted(entries):
            sub_path = root / sub_name
            sub_info = os.lstat(sub_path)
            if stat.S_ISLNK(sub_info.st_mode) or not stat.S_ISDIR(sub_info.st_mode) or sub_info.st_uid != os.geteuid():
                return False
            for child_name in sorted(os.listdir(sub_path)):
                child_path = sub_path / child_name
                cinfo = os.lstat(child_path)
                if stat.S_ISLNK(cinfo.st_mode) or cinfo.st_uid != os.geteuid():
                    return False
                if stat.S_ISDIR(cinfo.st_mode):
                    if sub_name != "transport" or child_name != "gh-config":
                        return False
                    for gname in sorted(os.listdir(child_path)):
                        gpath = child_path / gname
                        ginfo = os.lstat(gpath)
                        if not stat.S_ISREG(ginfo.st_mode) or ginfo.st_nlink != 1 or ginfo.st_uid != os.geteuid():
                            return False
                        os.unlink(gpath)
                    os.rmdir(child_path)
                elif stat.S_ISREG(cinfo.st_mode) and cinfo.st_nlink == 1:
                    os.unlink(child_path)
                else:
                    return False
            os.rmdir(sub_path)
        os.rmdir(root)
        return True
    except OSError:
        return False
