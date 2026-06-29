from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader
import fitz  # PyMuPDF
import os
import json

def load_pdf(path, source_name):
    print(f"Reading PDF: {path}")

    # Try pypdf first
    try:
        reader = PdfReader(path)
        pages = []
        for i, page in enumerate(reader.pages):
            text = page.extract_text()
            if text and text.strip() and len(text.strip()) > 50:
                pages.append({
                    "text": text,
                    "page": i + 1,
                    "source": source_name
                })
        if len(pages) >= 10:
            print(f"  pypdf: loaded {len(pages)} pages")
            return pages
        print(f"  pypdf got only {len(pages)} pages, switching to PyMuPDF...")
    except Exception as e:
        print(f"  pypdf failed: {e}, switching to PyMuPDF...")

    # Fall back to PyMuPDF
    pages = []
    doc = fitz.open(path)
    for i, page in enumerate(doc):
        text = page.get_text()
        if text and text.strip() and len(text.strip()) > 50:
            pages.append({
                "text": text,
                "page": i + 1,
                "source": source_name
            })
    doc.close()
    print(f"  PyMuPDF: loaded {len(pages)} pages")
    return pages


def flatten_json(obj, prefix=""):
    """Recursively flatten a JSON object into key: value strings."""
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            lines.extend(flatten_json(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            lines.extend(flatten_json(item, f"{prefix}[{i}]"))
    else:
        if str(obj).strip():
            lines.append(f"{prefix}: {obj}")
    return lines


def load_json(path, source_name):
    """
    Load a JSON file and convert its contents to text chunks.
    Handles three shapes:
      - A list of objects  → each object becomes one "page"
      - A dict with a list → each item in the list becomes one "page"
      - Any other dict     → the whole file becomes one "page"
    """
    print(f"Reading JSON: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    pages = []

    def record_to_text(record, index):
        """Turn one record (dict, list, or scalar) into a readable string."""
        if isinstance(record, dict):
            lines = flatten_json(record)
            return "\n".join(lines)
        elif isinstance(record, list):
            lines = flatten_json(record)
            return "\n".join(lines)
        else:
            return str(record)

    if isinstance(data, list):
        # Top-level array: treat each element as a separate "page"
        for i, item in enumerate(data):
            text = record_to_text(item, i)
            if text.strip() and len(text.strip()) > 20:
                pages.append({
                    "text": text,
                    "page": i + 1,
                    "source": source_name
                })

    elif isinstance(data, dict):
        # Look for a key whose value is a list (common pattern)
        list_key = next((k for k, v in data.items() if isinstance(v, list)), None)
        if list_key:
            for i, item in enumerate(data[list_key]):
                text = record_to_text(item, i)
                if text.strip() and len(text.strip()) > 20:
                    pages.append({
                        "text": text,
                        "page": i + 1,
                        "source": source_name
                    })
        else:
            # Flat dict: whole file = one page
            text = record_to_text(data, 0)
            if text.strip():
                pages.append({
                    "text": text,
                    "page": 1,
                    "source": source_name
                })

    print(f"  JSON: loaded {len(pages)} records as pages")
    return pages
def load_mitre_attack(path, source_name):
    """
    Specialized loader for MITRE ATT&CK Enterprise STIX JSON.
    Extracts container/K8s-relevant techniques as rich semantic chunks
    instead of the generic flatten_json approach.
    """
    print(f"Reading MITRE ATT&CK JSON: {path}")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])

    # Index mitigations by STIX ID
    mitigations = {o["id"]: o.get("description", "")
                   for o in objects
                   if o.get("type") == "course-of-action" and not o.get("revoked")}

    # Map technique STIX ID → list of mitigation texts
    tech_mits: dict[str, list[str]] = {}
    for o in objects:
        if (o.get("type") == "relationship"
                and o.get("relationship_type") == "mitigates"
                and o.get("source_ref") in mitigations):
            tech_mits.setdefault(o["target_ref"], []).append(
                mitigations[o["source_ref"]])

    k8s_keywords = [
        "container", "kubernetes", "docker", "pod ", "etcd", "kubelet",
        "kube-", "kubectl", "namespace", "orchestrat", "registry",
        "image", "cluster", "serviceaccount", "rbac", "privilege", "root",
    ]

    pages = []
    seen = set()

    for obj in objects:
        if obj.get("type") != "attack-pattern": continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"): continue

        platforms = [p.lower() for p in obj.get("x_mitre_platforms", [])]
        name = obj.get("name", "")
        desc = obj.get("description", "")
        low  = (desc + " " + name).lower()

        if not ("containers" in platforms or
                any(k in low for k in k8s_keywords)):
            continue

        ext_refs  = obj.get("external_references", [])
        attack_id = next((e["external_id"] for e in ext_refs
                          if e.get("source_name") == "mitre-attack"), "")
        if not attack_id or attack_id in seen:
            continue
        seen.add(attack_id)

        tactics   = [k["phase_name"] for k in obj.get("kill_chain_phases", [])]
        detection = obj.get("x_mitre_detection", "")
        mit_texts = tech_mits.get(obj["id"], [])

        parts = [
            f"MITRE ATT&CK: {attack_id} — {name}",
            f"Tactics: {', '.join(tactics)}",
            f"Platforms: {', '.join(platforms)}",
            f"Description: {desc}",
        ]
        if detection:
            parts.append(f"Detection: {detection}")
        if mit_texts:
            parts.append("Mitigations: " + " | ".join(m[:300] for m in mit_texts[:3]))

        pages.append({
            "text": "\n".join(parts),
            "page": len(pages) + 1,
            "source": source_name
        })

    print(f"  MITRE ATT&CK: loaded {len(pages)} container/K8s technique documents")
    return pages


def split_into_chunks(pages):
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        separators=["\n\n", "\n", ". ", " "]
    )
    all_chunks = []
    all_metadata = []

    for page in pages:
        chunks = splitter.split_text(page["text"])
        for chunk in chunks:
            all_chunks.append(chunk)
            all_metadata.append({
                "page": page["page"],
                "source": page["source"]
            })

    return all_chunks, all_metadata


def store_in_chromadb(chunks, metadata):
    print(f"\nLoading embedding model...")
    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2"
    )

    print(f"Storing {len(chunks)} chunks in ChromaDB...")
    vectorstore = Chroma.from_texts(
        texts=chunks,
        embedding=embeddings,
        metadatas=metadata,
        persist_directory="./chroma_db"
    )
    print(f"Done!")
    return vectorstore


def load_file(path, source_name):
    """Dispatch to the right loader based on file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json" and "enterprise-attack" in path:  # ← ADD THIS LINE
        return load_mitre_attack(path, source_name)     # ← AND THIS LINE
    elif ext == ".json":
        return load_json(path, source_name)
    elif ext == ".pdf":
        return load_pdf(path, source_name)
    else:
        print(f"WARNING: Unsupported file type '{ext}' for {path} — skipping")
        return []


if __name__ == "__main__":
    import argparse
    import shutil
    from datetime import datetime, timezone

    parser = argparse.ArgumentParser()
    parser.add_argument("--rebuild", action="store_true",
                        help="Wipe and rebuild ChromaDB from scratch")
    args = parser.parse_args()

    files = [
        ("./data/cis_k8s.pdf",        "cis_k8s"),
        ("./data/nist_800_53.pdf",     "nist_800_53"),
        ("./data/nsa_k8s.pdf",         "nsa_k8s"),
        ("./data/hipaa_security.pdf",  "hipaa_security"),
        ("./data/nsa_k8s_v1_2.pdf",    "nsa_k8s_v1_2"),
        ("./data/nist_hipaa.pdf",      "nist_hipaa"),
        ("./data/pci_dss_v4.pdf",      "pci_dss_v4"),
        ("./data/enterprise-attack.json","enterprise-attack"),

        # Add JSON files here just like PDFs:
        # ("./data/my_controls.json",  "my_controls"),
    ]

    all_chunks = []
    all_metadata = []

    for path, source in files:
        if not os.path.exists(path):
            print(f"WARNING: {path} not found — skipping")
            continue
        pages = load_file(path, source)
        chunks, metadata = split_into_chunks(pages)
        all_chunks.extend(chunks)
        all_metadata.extend(metadata)
        print(f"  {source}: {len(chunks)} chunks")

    print(f"\nTotal: {len(all_chunks)} chunks")

    if args.rebuild:
        if os.path.exists("./chroma_db"):
            backup = f"./chroma_db_backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            shutil.copytree("./chroma_db", backup)
            print(f"Backed up existing DB to {backup}")
            shutil.rmtree("./chroma_db")
            print("Cleared old ChromaDB")
    else:
        print("Running in additive mode. Use --rebuild to wipe and rebuild.")

    store_in_chromadb(all_chunks, all_metadata)
    print("\n✅ All standards ingested!")