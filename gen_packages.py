import os, hashlib, gzip, bz2, tarfile, io, lzma

pool_root = "pool"
packages_lines = []

for dirpath, dirnames, filenames in os.walk(pool_root):
    for fn in sorted(filenames):
        if not fn.endswith(".deb"):
            continue
        full = os.path.join(dirpath, fn)
        rel  = full.replace(os.sep, "/")
        size = os.path.getsize(full)
        with open(full, "rb") as f:
            raw = f.read()
        md5    = hashlib.md5(raw).hexdigest()
        sha1   = hashlib.sha1(raw).hexdigest()
        sha256 = hashlib.sha256(raw).hexdigest()
        pos = 8
        ctrl_data = ""
        while pos < len(raw) - 60:
            name = raw[pos:pos+16].decode("ascii", "replace").strip()
            sz   = int(raw[pos+48:pos+58].decode("ascii", "replace").strip())
            data = raw[pos+60:pos+60+sz]
            pos  = pos + 60 + sz + (sz % 2)
            if name.startswith("control.tar"):
                if name.endswith(".gz"):
                    tf = tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)))
                elif name.endswith(".xz"):
                    tf = tarfile.open(fileobj=io.BytesIO(lzma.decompress(data)))
                else:
                    tf = tarfile.open(fileobj=io.BytesIO(data))
                for m in tf.getmembers():
                    if m.name.endswith("control"):
                        ctrl_data = tf.extractfile(m).read().decode()
                        break
                break
        packages_lines.append(ctrl_data.strip())
        packages_lines.append("Filename: " + rel)
        packages_lines.append("Size: " + str(size))
        packages_lines.append("MD5sum: " + md5)
        packages_lines.append("SHA1: " + sha1)
        packages_lines.append("SHA256: " + sha256)
        packages_lines.append("")

pkgs = "\n".join(packages_lines) + "\n"
open("Packages", "w", encoding="utf-8").write(pkgs)
open("Packages.bz2", "wb").write(bz2.compress(pkgs.encode()))
print("OK:", pkgs.count("Package:"), "packages")
