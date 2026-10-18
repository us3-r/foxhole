"""Guest-only scanner worker. The broker supplies a Job Object, time and output budgets.

This module has no networking or sample execution API. Tests use generated harmless bytes.
Runtime dependencies are installed offline into the immutable guest image.
"""
import base64
import contextlib
import hashlib
import importlib.metadata
import io
import ipaddress
import json
import os
import re
import struct
import sys
import tempfile
import time
import zipfile

VERSIONS = {"yara": "4.5.2", "pe": "2024.8.26", "capa": "9.2.1", "network": "foxhole-packet-1"}


class LimitError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def plain_file(path, maximum):
    # Broker pins ancestors and files on Windows for the lifetime of the worker.
    for parent in [path] + list(__import__("pathlib").Path(path).parents):
        meta = os.lstat(parent)
        if os.path.islink(parent) or getattr(meta, "st_file_attributes", 0) & 0x400:
            raise ValueError("reparse_point")
    with open(path, "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise LimitError("input_limit")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def bounded_json(data, limits):
    if len(data) > limits["output_bytes"]:
        raise LimitError("output_limit")
    result = json.loads(data, object_pairs_hook=unique_object)
    stack = [(result, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > limits["depth"] or nodes > limits["output_bytes"] // 2:
            raise LimitError("json_structure_limit")
        if isinstance(value, str) and len(value.encode()) > limits["string_bytes"]:
            raise LimitError("string_limit")
        if isinstance(value, (dict, list)):
            if len(value) > max(limits["packets"], limits["strings"], limits["rules"]):
                raise LimitError("array_limit")
            stack.extend((child, depth + 1) for child in (value.values() if isinstance(value, dict) else value))
    return result


def warn(result, code):
    if not any(w["code"] == code for w in result["warnings"]):
        result["warnings"].append({"code": code, "message": code.replace("_", " ")})
    if result["status"] == "completed":
        result["status"] = "partial"


def bounded(values, maximum, result):
    values = list(values)
    if len(values) > maximum:
        result["truncated"] = True
        warn(result, "result_count_limit")
    return values[:maximum]


def text(value, result):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value)
    encoded = value.encode()
    if len(encoded) > result["limits"]["string_bytes"]:
        warn(result, "display_value_truncated")
        result["truncated"] = True
        value = encoded[:result["limits"]["string_bytes"]].decode("utf-8", "ignore")
    return value


def pack_bytes(config, result, user=False):
    pack = config["user_rules" if user else "rules"]
    if not pack:
        raise FileNotFoundError("rule_pack_unavailable")
    data = plain_file(pack["path"], min(result["limits"]["input_bytes"], 32 * 1024 * 1024))
    if digest(data) != pack["sha256"].lower():
        raise ValueError("rule_pack_integrity_mismatch")
    result["rule_packs"].append({k: pack[k] for k in ("id", "version", "sha256")} | {"trusted": not user})
    return data


def finding(rule, namespace, pack, result):
    return dict(id="match:" + digest((pack + ":" + namespace + ":" + rule).encode())[:32],
                rule=text(rule, result), namespace=text(namespace, result), title=text(rule, result),
                tags=[], metadata={}, attack=[], mbc=[], maec={}, scope="file", locations=[],
                features=[], rule_pack=pack, evidence_ids=[result["target"]])


def yara_scan(data, config, result):
    import yara
    if yara.__version__ != VERSIONS["yara"]:
        raise ValueError("unsupported_engine_version")
    sources = {"foxhole": pack_bytes(config, result).decode("utf-8")}
    if config["user_rules"]:
        sources["user"] = pack_bytes(config, result, True).decode("utf-8")
    # Complete compilation precedes every scan. Includes are forbidden, namespaces are separate.
    rules = yara.compile(sources=sources, includes=False, error_on_warning=True)
    if sum(1 for _ in rules) > result["limits"]["rules"]:
        raise LimitError("rule_count_limit")
    yara.set_config(stack_size=16384, max_strings_per_rule=1000,
                    max_match_data=result["limits"]["match_bytes"])
    count = 0
    def callback(match):
        nonlocal count
        if not match["matches"]:
            return yara.CALLBACK_CONTINUE
        if count >= result["limits"]["findings"]:
            result["truncated"] = True
            warn(result, "finding_limit")
            return yara.CALLBACK_ABORT
        count += 1
        pack = config["user_rules" if match["namespace"] == "user" else "rules"]["id"]
        item = finding(match["rule"], match["namespace"], pack, result)
        item["tags"] = bounded(sorted(match["tags"]), 64, result)
        item["metadata"] = {text(k, result): text(v, result) for k, v in sorted(match["meta"].items())[:64]}
        offsets = set()
        for string in match["strings"]:
            for instance in string.instances:
                key = (instance.offset, instance.matched_length, instance.matched_data.hex())
                if len(offsets) >= result["limits"]["offsets"] and key not in offsets:
                    result["truncated"] = True
                    warn(result, "match_offset_limit")
                    break
                offsets.add(key)
        item["locations"] = [dict(kind="file", offset=o, length=n,
                                  excerpt_hex=h[:result["limits"]["match_bytes"] * 2]) for o, n, h in sorted(offsets)]
        result["findings"].append(item)
        return yara.CALLBACK_CONTINUE
    rules.match(data=data, timeout=result["limits"]["timeout_seconds"], callback=callback,
                which_callbacks=yara.CALLBACK_MATCHES)


def strings_scan(data, result):
    maximum = result["limits"]["strings"]
    strings = set()
    patterns = [(rb"[\x20-\x7e]{5,}", "ascii"), (rb"(?:[\x20-\x7e]\x00){5,}", "utf16le")]
    for pattern, method in patterns:
        for match in re.finditer(pattern, data):
            if len(strings) >= maximum:
                result["truncated"] = True
                warn(result, "string_count_limit")
                break
            raw = match.group().decode("utf-16le" if method == "utf16le" else "ascii")
            strings.add((text(raw, result), method, match.start()))
            if method == "ascii" and 8 <= len(raw) <= result["limits"]["string_bytes"] and len(raw) % 4 == 0:
                try:
                    decoded = base64.b64decode(raw, validate=True)
                    if len(decoded) >= 5 and all(32 <= b <= 126 for b in decoded) and len(strings) < maximum:
                        strings.add((decoded.decode("ascii"), "base64", match.start()))
                except ValueError:
                    pass
    result["strings"] = [dict(value=v, method=m, offset=o) for v, m, o in sorted(strings)]


def authenticode_offline(path):
    if os.name != "nt" or path is None:
        return "verification_unavailable"
    import ctypes
    from ctypes import wintypes
    class GUID(ctypes.Structure):
        _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]
    class FileInfo(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("path", wintypes.LPCWSTR), ("handle", wintypes.HANDLE), ("subject", ctypes.c_void_p)]
    class TrustData(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("policy", ctypes.c_void_p), ("sip", ctypes.c_void_p),
                    ("ui", wintypes.DWORD), ("revocation", wintypes.DWORD), ("choice", wintypes.DWORD),
                    ("file", ctypes.POINTER(FileInfo)), ("state_action", wintypes.DWORD), ("state", wintypes.HANDLE),
                    ("url", wintypes.LPCWSTR), ("flags", wintypes.DWORD), ("context", wintypes.DWORD), ("signature", ctypes.c_void_p)]
    action = GUID(0x00aac56b, 0xcd44, 0x11d0, (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
    file = FileInfo(ctypes.sizeof(FileInfo), str(path), None, None)
    trust = TrustData()
    trust.size, trust.ui, trust.choice, trust.file, trust.state_action = ctypes.sizeof(TrustData), 2, 1, ctypes.pointer(file), 1
    # WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE: no network retrieval.
    trust.flags = 0x1000 | 0x10
    verify = ctypes.WinDLL("wintrust", use_last_error=True).WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(TrustData)]
    verify.restype = ctypes.c_long
    try:
        status = verify(wintypes.HWND(-1), ctypes.byref(action), ctypes.byref(trust)) & 0xffffffff
    finally:
        trust.state_action = 2
        verify(wintypes.HWND(-1), ctypes.byref(action), ctypes.byref(trust))
    return {0: "valid_offline_trust", 0x80096010: "invalid_signature_digest", 0x800b0109: "untrusted_chain", 0x800b0101: "certificate_time_invalid", 0x800b0100: "unsigned"}.get(status, "verification_inconclusive")


def pe_scan(data, config, result, path=None):
    strings_scan(data, result)
    if not data.startswith(b"MZ"):
        result["status"] = "skipped"
        warn(result, "unsupported_pe_format_strings_retained")
        return
    import pefile
    if pefile.__version__ != VERSIONS["pe"]:
        raise ValueError("unsupported_engine_version")
    pe = pefile.PE(data=data, fast_load=True)
    if pe.FILE_HEADER.NumberOfSections > 96:
        raise LimitError("section_count_limit")
    pe.parse_data_directories(directories=[0, 1, 2, 6, 9, 13])
    limits = result["limits"]
    sections = []
    for s in pe.sections:
        start, size = s.PointerToRawData, s.SizeOfRawData
        if start + size > len(data):
            raise ValueError("invalid_section_bounds")
        sections.append(dict(name=text(s.Name.rstrip(b"\0"), result), raw_size=size,
                             virtual_size=s.Misc_VirtualSize, offset=start,
                             entropy=round(s.get_entropy(), 6),
                             permissions="".join(letter for flag, letter in [(0x40000000, "R"), (0x80000000, "W"), (0x20000000, "X")] if s.Characteristics & flag),
                             sha256=digest(data[start:start + size])))
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) + getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        imports.extend(text(entry.dll, result) + "!" + (text(i.name, result) if i.name else "ordinal:" + str(i.ordinal)) for i in entry.imports)
    exports = [text(e.name, result) if e.name else "ordinal:" + str(e.ordinal) for e in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]
    resources, stack = [], [(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limits["depth"]:
            raise LimitError("resource_depth_limit")
        for entry in getattr(node, "entries", []):
            if hasattr(entry, "directory"):
                stack.append((entry.directory, depth + 1))
            if hasattr(entry, "data"):
                resources.append(f"rva:{entry.data.struct.OffsetToData}:size:{entry.data.struct.Size}")
            if len(resources) + len(stack) > limits["features"]:
                warn(result, "resource_count_limit")
                stack.clear()
                break
    debug = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        debug.append(f"type:{entry.struct.Type}:size:{entry.struct.SizeOfData}")
        # PDB paths are deliberately excluded; they may identify a host/user.
    tls = []
    directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if directory:
        width = 8 if pe.PE_TYPE == 0x20b else 4
        rva = directory.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        if rva > 0:
            for index in range(limits["offsets"]):
                raw = pe.get_data(rva + width * index, width)
                if len(raw) != width:
                    warn(result, "tls_callback_table_truncated")
                    break
                address = int.from_bytes(raw, "little")
                if not address:
                    break
                tls.append(address)
            else:
                warn(result, "tls_callback_limit")
    overlay = pe.get_overlay_data_start_offset()
    cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    certificates = []
    signature = "unsigned" if not cert.Size else "present_not_verified"
    if cert.Size:
        signature = authenticode_offline(path)
        warn(result, "offline_signature_revocation_and_signer_reputation_not_checked")
        if cert.VirtualAddress + cert.Size > len(data) or cert.Size < 8:
            raise ValueError("certificate_bounds")
        try:
            if importlib.metadata.version("cryptography") != "46.0.5":
                raise ValueError("unsupported_certificate_parser_version")
            from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
            from cryptography.hazmat.primitives import hashes
            for certificate in load_der_pkcs7_certificates(data[cert.VirtualAddress + 8:cert.VirtualAddress + cert.Size])[:16]:
                certificates.append(dict(subject=text(certificate.subject.rfc4514_string(), result),
                                         issuer=text(certificate.issuer.rfc4514_string(), result),
                                         sha256=certificate.fingerprint(hashes.SHA256()).hex(),
                                         serial=hex(certificate.serial_number)))
        except ImportError:
            warn(result, "certificate_parser_unavailable")
        except ValueError:
            warn(result, "invalid_certificate_metadata")
    authentihash = None
    fuzzy = None
    try:
        import lief
        if not lief.__version__.startswith("0.16.6"):
            raise ValueError("unsupported_lief_version")
        parsed = lief.PE.parse(list(data))
        authentihash = bytes(parsed.authentihash_sha256).hex()
    except ImportError:
        warn(result, "authentihash_unavailable")
    try:
        import tlsh
        if importlib.metadata.version("py-tlsh") != "4.5.0":
            raise ValueError("unsupported_tlsh_version")
        hashed = tlsh.hash(data)
        fuzzy = "tlsh:" + hashed if hashed != "TNULL" else None
    except ImportError:
        warn(result, "tlsh_unavailable")
    embedded = []
    for m in re.finditer(b"MZ", data[2:]):
        offset = m.start() + 2
        if offset + 64 <= len(data):
            pointer = offset + struct.unpack_from("<I", data, offset + 60)[0]
            if data[pointer:pointer + 4] == b"PE\0\0":
                embedded.append(offset)
                if len(embedded) >= limits["offsets"]:
                    warn(result, "embedded_pe_limit")
                    break
    markers = [s["name"] for s in sections if s["name"].upper().startswith(("UPX", "ASPACK", ".VMP"))]
    result["pe"] = dict(architecture={0x14c: "x86", 0x8664: "x86_64", 0xaa64: "arm64"}.get(pe.FILE_HEADER.Machine, f"machine:{pe.FILE_HEADER.Machine}"),
                        subsystem=pe.OPTIONAL_HEADER.Subsystem, entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                        image_base=pe.OPTIONAL_HEADER.ImageBase, compile_timestamp_untrusted=pe.FILE_HEADER.TimeDateStamp,
                        sections=sections, imports=bounded(sorted(set(imports)), limits["features"], result),
                        exports=bounded(sorted(set(exports)), limits["features"], result),
                        resources=bounded(sorted(resources), limits["features"], result), debug=bounded(debug, 64, result),
                        overlay_size=len(data) - overlay if overlay is not None else 0,
                        authenticode_status=signature, certificates=certificates,
                        imphash=pe.get_imphash() or None, authentihash=authentihash, fuzzy_hash=fuzzy,
                        packer_compiler=["section_marker_untrusted:" + m for m in sorted(set(markers))],
                        tls_callbacks=tls, embedded_pe_offsets=embedded)
    if pe.get_warnings():
        warn(result, "pe_parser_reported_structural_warnings")


class OutputBuffer(io.StringIO):
    def __init__(self, maximum):
        super().__init__()
        self.maximum = maximum
        self.seen = 0
    def write(self, value):
        self.seen += len(value.encode())
        if self.seen > self.maximum:
            raise LimitError("capa_output_limit")
        return super().write(value)


def capa_document(document, config, result):
    # Native capa 9.2.1 validates its complete document using its versioned Pydantic model.
    from capa.render.result_document import ResultDocument
    model = ResultDocument.model_validate(document)
    doc = model.model_dump(mode="json", by_alias=True)
    if doc["meta"]["version"] != VERSIONS["capa"] or doc["meta"]["flavor"] != "static":
        raise ValueError("unsupported_capa_schema")
    if doc["meta"]["sample"]["sha256"].lower() != result["target_sha256"]:
        raise ValueError("capa_target_hash_mismatch")
    for name, rule in sorted(doc["rules"].items()):
        if len(result["findings"]) >= result["limits"]["findings"]:
            warn(result, "capa_finding_limit")
            result["truncated"] = True
            break
        meta = rule["meta"]
        item = finding(name, meta.get("namespace") or "", config["rules"]["id"], result)
        item["scope"] = str(meta["scopes"]["static"])
        item["attack"] = [x["id"] for x in meta.get("att&ck", [])]
        item["mbc"] = [x["id"] for x in meta.get("mbc", [])]
        item["maec"] = {k: text(v, result) for k, v in (meta.get("maec") or {}).items() if v is not None}
        features, locations = set(), set()
        stack = []
        for location, match in rule["matches"]:
            if isinstance(location["value"], int):
                locations.add((location["type"], location["value"]))
            stack.append((match, 0))
        while stack:
            match, depth = stack.pop()
            if depth > result["limits"]["depth"]:
                raise LimitError("capa_feature_depth")
            if not match["success"]:
                continue
            node = match["node"]
            if node["type"] == "feature":
                features.add(text(json.dumps(node["feature"], sort_keys=True, separators=(",", ":")), result))
                for loc in match["locations"]:
                    if isinstance(loc["value"], int):
                        locations.add((loc["type"], loc["value"]))
            if len(features) > result["limits"]["features"] or len(locations) > result["limits"]["offsets"]:
                warn(result, "capa_feature_limit")
                result["truncated"] = True
                break
            stack.extend((c, depth + 1) for c in match["children"])
        item["features"] = sorted(features)[:result["limits"]["features"]]
        item["locations"] = [dict(kind=k.replace("file", "file"), offset=o, length=0, excerpt_hex="")
                             for k, o in sorted(locations)[:result["limits"]["offsets"]]]
        result["findings"].append(item)


def capa_scan(data, config, result, path):
    if not data.startswith(b"MZ"):
        result["status"] = "skipped"
        warn(result, "unsupported_capa_input")
        return
    if importlib.metadata.version("flare-capa") != VERSIONS["capa"]:
        raise ValueError("unsupported_engine_version")
    import capa.main
    archive = pack_bytes(config, result)
    with tempfile.TemporaryDirectory(prefix="foxhole-capa-") as directory:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            infos = zipped.infolist()
            if len(infos) > result["limits"]["rules"] or sum(i.file_size for i in infos) > result["limits"]["input_bytes"]:
                raise LimitError("capa_rule_pack_limit")
            names = set()
            for entry in infos:
                name = entry.filename
                if name in names or name.startswith("/") or "\\" in name or ":" in name or any(p in (".", "..") for p in name.split("/")) or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("unsafe_rule_pack_path")
                names.add(name)
                if entry.is_dir():
                    continue
                if not name.endswith((".yml", ".yaml")):
                    continue
                destination = os.path.join(directory, name)
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with open(destination, "xb") as output:
                    output.write(zipped.read(entry))
        output = OutputBuffer(result["limits"]["output_bytes"])
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(OutputBuffer(65536)):
            code = capa.main.main(["-j", "-b", "vivisect", "-r", directory, "-s", directory, "--", path])
        if code:
            raise ValueError("capa_nonzero_exit")
        doc = bounded_json(output.getvalue().encode(), result["limits"])
        capa_document(doc, config, result)


def dns_name(data, offset):
    labels, seen, end = [], set(), None
    for _ in range(64):
        if offset >= len(data) or offset in seen:
            raise ValueError("invalid_dns_name")
        seen.add(offset)
        length = data[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        if length & 0xc0 == 0xc0:
            if offset >= len(data):
                raise ValueError("truncated_dns_pointer")
            if end is None:
                end = offset + 1
            offset = ((length & 63) << 8) | data[offset]
        else:
            if length > 63 or offset + length > len(data):
                raise ValueError("invalid_dns_label")
            labels.append(data[offset:offset + length].decode("ascii"))
            if sum(map(len, labels)) + len(labels) > 254:
                raise ValueError("oversized_dns_name")
            offset += length
    raise LimitError("dns_recursion_limit")


def dns_metadata(data, item):
    if len(data) < 12:
        raise ValueError("truncated_dns")
    _, flags, questions, answers, _, _ = struct.unpack_from("!6H", data)
    if questions != 1 or answers > 64:
        raise ValueError("unsupported_dns_counts")
    query, offset = dns_name(data, 12)
    item["dns_query"] = query
    offset += 4
    for _ in range(answers):
        owner, offset = dns_name(data, offset)
        kind, cls, _, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        answer = data[offset:offset + size]
        if len(answer) != size:
            raise ValueError("truncated_dns_answer")
        # Only direct A/AAAA owner relationships. CNAME chains are not guessed.
        if flags & 0x8000 and owner.lower() == query.lower() and cls == 1 and ((kind == 1 and size == 4) or (kind == 28 and size == 16)):
            item["dns_answers"].append(str(ipaddress.ip_address(answer)))
        offset += size


def tls_metadata(data, item):
    if len(data) < 9 or data[0] != 22:
        return
    size = int.from_bytes(data[3:5], "big")
    if size + 5 > len(data):
        raise ValueError("tls_record_requires_reassembly")
    kind, length = data[5], int.from_bytes(data[6:9], "big")
    hello = data[9:9 + length]
    if kind == 11:
        if len(hello) != length or len(hello) < 6:
            raise ValueError("truncated_tls_certificate")
        total = int.from_bytes(hello[:3], "big")
        if total != len(hello) - 3:
            raise ValueError("invalid_tls_certificate_list")
        size = int.from_bytes(hello[3:6], "big")
        certificate = hello[6:6 + size]
        if size == 0 or size > 65536 or len(certificate) != size:
            raise ValueError("tls_certificate_limit")
        item["tls"]["certificate_sha256"] = digest(certificate)
        try:
            from cryptography.x509 import load_der_x509_certificate
            cert = load_der_x509_certificate(certificate)
            item["tls"]["certificate_subject"] = cert.subject.rfc4514_string()[:1024]
            item["tls"]["certificate_issuer"] = cert.issuer.rfc4514_string()[:1024]
            item["tls"]["certificate_serial"] = hex(cert.serial_number)
        except (ImportError, ValueError):
            item["tls"]["certificate_metadata_status"] = "unavailable_or_invalid"
        return
    if len(hello) != length or kind not in (1, 2):
        return
    version = int.from_bytes(hello[:2], "big")
    cursor = 34
    cursor += 1 + hello[cursor]
    ciphers = []
    if kind == 1:
        n = int.from_bytes(hello[cursor:cursor + 2], "big")
        cursor += 2
        ciphers = list(struct.unpack("!" + "H" * (n // 2), hello[cursor:cursor + n]))
        cursor += n
        cursor += 1 + hello[cursor]
    else:
        ciphers = [int.from_bytes(hello[cursor:cursor + 2], "big")]
        cursor += 3
    extensions, groups, points = [], [], []
    end = cursor + 2 + int.from_bytes(hello[cursor:cursor + 2], "big")
    cursor += 2
    if end > len(hello):
        raise ValueError("truncated_tls_extensions")
    while cursor < end:
        ext, n = struct.unpack_from("!HH", hello, cursor)
        cursor += 4
        body = hello[cursor:cursor + n]
        if len(body) != n or cursor + n > end:
            raise ValueError("truncated_tls_extension")
        extensions.append(ext)
        if ext == 0 and len(body) >= 5 and body[2] == 0:
            size = int.from_bytes(body[3:5], "big")
            if len(body[5:5 + size]) != size:
                raise ValueError("truncated_sni")
            item["tls_sni"] = body[5:5 + size].decode("ascii")
        if ext == 10 and len(body) >= 2:
            groups = [int.from_bytes(body[i:i + 2], "big") for i in range(2, len(body), 2)]
        if ext == 11 and body:
            points = list(body[1:])
        cursor += n
    def numbers(values):
        return "-".join(str(v) for v in values if v & 0x0f0f != 0x0a0a)
    parts = [str(version), numbers(ciphers), numbers(extensions)]
    if kind == 1:
        parts += [numbers(groups), numbers(points)]
    item["tls"]["ja3" if kind == 1 else "ja3s"] = hashlib.md5(",".join(parts).encode(), usedforsecurity=False).hexdigest()
    item["tls"]["record_version"] = str(version)
    item["tls"]["visibility"] = "handshake_only_encrypted_http_not_inspected"


def packet_metadata(frame, link, index, timestamp, result):
    cursor = 0
    if link == 1:
        if len(frame) < 14:
            raise ValueError("truncated_ethernet")
        ethertype = int.from_bytes(frame[12:14], "big")
        cursor = 14
        if ethertype == 0x8100:
            ethertype = int.from_bytes(frame[16:18], "big")
            cursor = 18
        if ethertype not in (0x800, 0x86dd):
            return None
    elif link not in (101, 228, 229):
        raise ValueError("unsupported_capture_link_type")
    data = frame[cursor:]
    if not data:
        raise ValueError("truncated_ip")
    if data[0] >> 4 == 4:
        if len(data) < 20 or data[0] & 15 < 5:
            raise ValueError("truncated_ipv4")
        if int.from_bytes(data[6:8], "big") & 0x3fff:
            raise ValueError("ip_fragment_requires_reassembly")
        size = int.from_bytes(data[2:4], "big")
        if size > len(data):
            raise ValueError("truncated_ipv4_packet")
        source, destination = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
        protocol, payload = data[9], data[(data[0] & 15) * 4:size]
    elif data[0] >> 4 == 6:
        if len(data) < 40 or 40 + int.from_bytes(data[4:6], "big") > len(data):
            raise ValueError("truncated_ipv6")
        source, destination = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
        protocol, payload = data[6], data[40:40 + int.from_bytes(data[4:6], "big")]
        if protocol not in (6, 17, 58):
            raise ValueError("ipv6_extension_requires_reassembly")
    else:
        raise ValueError("unsupported_ip_version")
    sport = dport = 0
    if protocol in (6, 17):
        if len(payload) < (20 if protocol == 6 else 8):
            raise ValueError("truncated_transport")
        sport, dport = struct.unpack_from("!HH", payload)
        header = (payload[12] >> 4) * 4 if protocol == 6 else 8
        if header > len(payload) or header < (20 if protocol == 6 else 8):
            raise ValueError("invalid_transport_header")
        payload = payload[header:]
    flow = digest(json.dumps(sorted([(source, sport), (destination, dport)]) + [protocol]).encode())[:32]
    item = dict(id=f"packet:{index}", packet=index, timestamp_us=timestamp, flow=flow,
                source=source, destination=destination, source_port=sport, destination_port=dport,
                protocol={6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(protocol, str(protocol)),
                direction="unknown", bytes=len(frame), dns_query=None, dns_answers=[],
                http_method=None, http_host=None, http_path=None, user_agent=None, tls_sni=None,
                tls={}, evidence_ids=[result["target"]])
    if protocol == 17 and 53 in (sport, dport):
        dns_metadata(payload, item)
    if protocol == 6:
        if re.match(rb"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|PATCH) ", payload):
            header, separator, _ = payload.partition(b"\r\n\r\n")
            if not separator or len(header) > result["limits"]["string_bytes"]:
                raise ValueError("http_headers_require_reassembly_or_exceed_limit")
            lines = header.decode("ascii").split("\r\n")
            method, path, version = lines[0].split(" ")
            if not version.startswith("HTTP/1."):
                raise ValueError("unsupported_http_version")
            item["http_method"], item["http_path"] = method, path.split("?", 1)[0]
            for line in lines[1:]:
                key, _, value = line.partition(":")
                if key.lower() == "host":
                    item["http_host"] = value.strip()
                if key.lower() == "user-agent":
                    item["user_agent"] = value.strip()
        tls_metadata(payload, item)
    return item


def network_scan(data, config, result):
    rules = bounded_json(pack_bytes(config, result), result["limits"])
    if set(rules) != {"schema_version", "rules"} or rules["schema_version"] != 1:
        raise ValueError("unsupported_network_rule_schema")
    if len(rules["rules"]) > result["limits"]["rules"]:
        raise LimitError("network_rule_count")
    names = set()
    for rule in rules["rules"]:
        if set(rule) != {"id", "field", "equals"} or rule["id"] in names or rule["field"] not in ("dns_query", "http_host", "user_agent", "tls_sni", "destination") or not isinstance(rule["equals"], str):
            raise ValueError("unsupported_network_rule")
        names.add(rule["id"])
    if not data:
        warn(result, "empty_capture")
        return
    offset, endian, interfaces, count, flows = 0, None, [], 0, set()
    while offset < len(data):
        if offset + 12 > len(data):
            warn(result, "truncated_capture_block")
            break
        block = data[offset:offset + 4]
        if block == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            interfaces = []
        if endian is None:
            raise ValueError("invalid_pcapng_section")
        kind, size = struct.unpack_from(endian + "II", data, offset)
        if size < 12 or size % 4 or offset + size > len(data):
            warn(result, "malformed_or_truncated_capture_block")
            break
        if struct.unpack_from(endian + "I", data, offset + size - 4)[0] != size:
            raise ValueError("pcapng_block_length_mismatch")
        body = data[offset + 8:offset + size - 4]
        if kind == 0x0a0d0d0a:
            if len(body) < 16 or struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise ValueError("unsupported_pcapng_version")
        elif kind == 1:
            if len(body) < 8 or len(interfaces) >= 64:
                raise LimitError("pcapng_interface_limit")
            link = struct.unpack_from(endian + "H", body)[0]
            resolution, shift, cursor = 1000000, 0, 8
            while cursor + 4 <= len(body):
                code, n = struct.unpack_from(endian + "HH", body, cursor)
                cursor += 4
                option = body[cursor:cursor + n]
                if len(option) != n:
                    raise ValueError("truncated_pcapng_option")
                if code == 9 and n == 1:
                    exponent = option[0] & 127
                    if exponent > 32:
                        raise ValueError("unsupported_timestamp_resolution")
                    resolution = (2 if option[0] & 128 else 10) ** exponent
                if code == 14 and n == 8:
                    shift = struct.unpack(endian + "q", option)[0] * 1000000
                cursor += (n + 3) & ~3
                if code == 0:
                    break
            interfaces.append((link, resolution, shift))
        elif kind == 6:
            if len(body) < 20:
                raise ValueError("truncated_packet_block")
            interface, high, low, captured, original = struct.unpack_from(endian + "5I", body)
            count += 1
            if count > result["limits"]["packets"]:
                warn(result, "packet_count_limit")
                result["truncated"] = True
                break
            if interface >= len(interfaces) or captured > len(body) - 20 or captured > original:
                raise ValueError("invalid_packet_block")
            if captured < original:
                warn(result, "capture_packet_truncated")
            link, resolution, shift = interfaces[interface]
            timestamp = ((high << 32) | low) * 1000000 // resolution + shift
            if timestamp < 0 or timestamp > 2**64 - 1:
                raise ValueError("invalid_packet_timestamp")
            try:
                item = packet_metadata(body[20:20 + captured], link, count, timestamp, result)
            except (ValueError, IndexError, struct.error, UnicodeError):
                warn(result, "packet_metadata_incomplete_or_malformed")
                continue
            if item:
                flows.add(item["flow"])
                if len(flows) > result["limits"]["flows"]:
                    warn(result, "flow_limit")
                    result["truncated"] = True
                    break
                result["packets"].append(item)
                for rule in rules["rules"]:
                    if item.get(rule["field"]) == rule["equals"]:
                        if len(result["findings"]) >= result["limits"]["findings"]:
                            warn(result, "network_alert_limit")
                            result["truncated"] = True
                            break
                        alert = finding(rule["id"], "foxhole/packet", config["rules"]["id"], result)
                        alert["id"] += f":{count}"
                        alert["locations"] = [dict(kind="packet", offset=count, length=0, excerpt_hex="")]
                        alert["features"] = [f"flow:{item['flow']}", f"timestamp_us:{timestamp}"]
                        result["findings"].append(alert)
        elif kind in (2, 3):
            warn(result, "unsupported_packet_block_type")
        offset += size
    if count == 0:
        warn(result, "no_packet_observations")
    # Scope limitation is explicit even on a capture without malformed packets.
    warn(result, "packet_local_analysis_no_tcp_reassembly_encrypted_http_not_inspected")


def analyze(request):
    stage, config = request["stage"], request["config"]
    result = dict(schema_version=1, scanner=stage, version=VERSIONS[stage], status="completed",
                  target=request["target"], target_sha256=request["target_sha256"],
                  started_at_ms=None, completed_at_ms=None, duration_ms=None, rule_packs=[],
                  limits=config["limits"], truncated=False, warnings=[], evidence_ids=[request["target"]],
                  original=None, findings=[], strings=[], pe=None, packets=[])
    try:
        data = plain_file(request["path"], config["limits"]["input_bytes"])
        if digest(data) != request["target_sha256"]:
            raise ValueError("target_hash_mismatch")
        if stage == "capa":
            capa_scan(data, config, result, request["path"])
        elif stage == "pe":
            pe_scan(data, config, result, request["path"])
        else:
            {"yara": yara_scan, "pe": pe_scan, "network": network_scan}[stage](data, config, result)
    except (ImportError, FileNotFoundError, importlib.metadata.PackageNotFoundError):
        result["status"] = "unavailable"
        warn(result, "scanner_or_rule_pack_unavailable")
    except LimitError:
        result["status"], result["truncated"] = "partial", True
        warn(result, "scanner_resource_limit")
    except Exception as error:
        result["status"] = "timed_out" if type(error).__name__ == "TimeoutError" else "invalid_output"
        # Exception strings, native diagnostics and host paths never cross the boundary.
        warn(result, "scanner_timeout" if result["status"] == "timed_out" else "scanner_rejected_input_or_schema")
    # Wall-clock duration is broker operational telemetry, excluded from stable result artifacts.
    result["duration_ms"] = None
    result["findings"].sort(key=lambda f: f["id"])
    result["warnings"].sort(key=lambda w: w["code"])
    return result


if __name__ == "__main__":
    request = json.loads(sys.stdin.buffer.read(65537), object_pairs_hook=unique_object)
    result = analyze(request)
    output = json.dumps(result, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    if len(output) > request["config"]["limits"]["output_bytes"]:
        result.update(status="partial", truncated=True, findings=[], strings=[], pe=None, packets=[])
        warn(result, "scanner_output_limit")
        output = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    sys.stdout.buffer.write(output)
