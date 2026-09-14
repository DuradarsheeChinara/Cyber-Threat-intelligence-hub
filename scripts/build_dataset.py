import csv
import json
import random
import re
import zipfile
from pathlib import Path
from collections import defaultdict

# ============================================================
# SETTINGS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "data"

# Maximum number kept for each category.
# 700 gives us a target of up to 3,500 records.
TARGET_PER_CATEGORY = 700

RANDOM_SEED = 42

CATEGORIES = [
    "Remote Code Execution",
    "Denial of Service",
    "Privilege Escalation",
    "SQL Injection",
    "Other",
]

random.seed(RANDOM_SEED)


# ============================================================
# FIND FILES
# ============================================================

def find_nvd_files():
    """
    Find the extracted NVD JSON files anywhere inside data/.
    """

    files = {}

    for year in ["2024", "2025", "2026"]:
        matches = list(DATA_DIR.rglob(f"nvdcve-2.0-{year}"))

        # Also check if Windows shows the extension differently.
        matches += list(DATA_DIR.rglob(f"nvdcve-2.0-{year}.json"))

        # Ignore directories
        matches = [p for p in matches if p.is_file()]

        if not matches:
            raise FileNotFoundError(
                f"Could not find the NVD {year} JSON file."
            )

        files[year] = matches[0]

    return files


def find_kev_file():
    """
    Find the CISA KEV JSON file.
    """

    possible_names = [
        "known_exploited_vulnerabilities",
        "known_exploited_vulnerabilities.json",
    ]

    for name in possible_names:
        matches = list(DATA_DIR.rglob(name))

        for match in matches:
            if match.is_file():
                return match

    raise FileNotFoundError(
        "Could not find known_exploited_vulnerabilities JSON file."
    )


# ============================================================
# CISA KEV
# ============================================================

def load_kev_ids(kev_file):
    """
    Load CVE IDs from the CISA Known Exploited Vulnerabilities
    catalog.
    """

    print("\nLoading CISA KEV data...")
    print(f"File: {kev_file}")

    with open(kev_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    kev_ids = set()

    for vulnerability in data.get("vulnerabilities", []):
        cve_id = vulnerability.get("cveID")

        if cve_id:
            kev_ids.add(cve_id.strip().upper())

    print(f"CISA KEV CVEs found: {len(kev_ids):,}")

    return kev_ids


# ============================================================
# TEXT HELPERS
# ============================================================

def get_description(cve):
    """
    Get the English CVE description.
    """

    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "").strip()

    if descriptions:
        return descriptions[0].get("value", "").strip()

    return ""


def get_cwes(cve):
    """
    Extract CWE identifiers from NVD.
    """

    cwes = []

    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")

            if value and value.startswith("CWE-"):
                cwes.append(value.upper())

    return list(dict.fromkeys(cwes))


# ============================================================
# CVSS
# ============================================================

def get_cvss_score(cve):
    """
    Extract the highest available CVSS score.

    Preference:
    CVSS v4 -> v3.1 -> v3.0 -> v2
    """

    metrics = cve.get("metrics", {})

    possible_scores = []

    # CVSS v4
    for item in metrics.get("cvssMetricV40", []):
        cvss_data = item.get("cvssData", {})
        score = cvss_data.get("baseScore")

        if isinstance(score, (int, float)):
            possible_scores.append(score)

    # CVSS v3.1
    for item in metrics.get("cvssMetricV31", []):
        cvss_data = item.get("cvssData", {})
        score = cvss_data.get("baseScore")

        if isinstance(score, (int, float)):
            possible_scores.append(score)

    # CVSS v3.0
    for item in metrics.get("cvssMetricV30", []):
        cvss_data = item.get("cvssData", {})
        score = cvss_data.get("baseScore")

        if isinstance(score, (int, float)):
            possible_scores.append(score)

    # CVSS v2
    for item in metrics.get("cvssMetricV2", []):
        cvss_data = item.get("cvssData", {})
        score = cvss_data.get("baseScore")

        if isinstance(score, (int, float)):
            possible_scores.append(score)

    if not possible_scores:
        return ""

    return max(possible_scores)


# ============================================================
# VENDOR / PRODUCT
# ============================================================

def extract_vendor_product(cve):
    """
    Extract vendor/product information from CPE configuration data.
    """

    vendors = []
    products = []

    configurations = cve.get("configurations", [])

    for configuration in configurations:

        nodes = configuration.get("nodes", [])

        for node in nodes:

            cpe_matches = node.get("cpeMatch", [])

            for cpe_match in cpe_matches:

                criteria = cpe_match.get("criteria", "")

                if not criteria.startswith("cpe:2.3:"):
                    continue

                parts = criteria.split(":")

                # CPE 2.3 format:
                # cpe:2.3:a:vendor:product:version:...

                if len(parts) >= 5:

                    vendor = parts[3]
                    product = parts[4]

                    if vendor and vendor != "*":
                        vendors.append(vendor.replace("\\", ""))

                    if product and product != "*":
                        products.append(product.replace("\\", ""))

    vendors = list(dict.fromkeys(vendors))
    products = list(dict.fromkeys(products))

    return (
        ", ".join(vendors[:5]),
        ", ".join(products[:5]),
    )


# ============================================================
# TITLE
# ============================================================

def create_title(cve_id, description):
    """
    Create a simple title from the CVE ID and description.
    """

    if not description:
        return cve_id

    # Keep title short.
    cleaned = re.sub(r"\s+", " ", description).strip()

    if len(cleaned) > 120:
        cleaned = cleaned[:117] + "..."

    return f"{cve_id} - {cleaned}"


# ============================================================
# CATEGORY CLASSIFICATION
# ============================================================

def classify_category(description, cwes):
    """
    Assign one of the project's five categories.

    This is an INITIAL automatic ground-truth labeling method.
    It deliberately uses both CWE information and description
    text rather than relying on one keyword alone.
    """

    text = description.lower()
    cwe_set = set(cwes)

    # --------------------------------------------------------
    # SQL INJECTION
    # --------------------------------------------------------

    sql_patterns = [
        r"\bsql injection\b",
        r"\bsql query injection\b",
        r"\binject.*sql",
        r"\bsql statement.*injection\b",
    ]

    for pattern in sql_patterns:
        if re.search(pattern, text):
            return "SQL Injection"

    # CWE supports an explicit SQL/data-query description; it is not enough
    # alone because CWE assignments can be broad or incomplete.
    if "CWE-89" in cwe_set and any(token in text for token in ["sql", "database", "query"]):
        return "SQL Injection"

    # --------------------------------------------------------
    # PRIVILEGE ESCALATION
    # --------------------------------------------------------

    privilege_cwes = {
        "CWE-269",
        "CWE-250",
        "CWE-266",
    }

    privilege_patterns = [
        r"privilege escalation",
        r"escalate.*privilege",
        r"elevate.*privilege",
        r"gain.*(?:root|administrator|admin|system).*privilege",
        r"obtain.*(?:root|administrator|admin|system).*privilege",
        r"gain.*system privileges",
    ]

    for pattern in privilege_patterns:
        if re.search(pattern, text):
            return "Privilege Escalation"

    if cwe_set.intersection(privilege_cwes) and any(token in text for token in ["privilege", "permission", "root", "administrator"]):
        return "Privilege Escalation"

    # --------------------------------------------------------
    # DENIAL OF SERVICE
    # --------------------------------------------------------

    dos_cwes = {
        "CWE-400",
        "CWE-770",
        "CWE-835",
        "CWE-834",
    }

    dos_patterns = [
        r"denial of service",
        r"\bdos\b",
        r"cause.*service.*unavailable",
        r"resource exhaustion",
        r"consume.*excessive.*resource",
        r"crash.*service",
        r"caus.*application.*crash",
        r"caus.*system.*crash",
    ]

    for pattern in dos_patterns:
        if re.search(pattern, text):
            return "Denial of Service"

    if cwe_set.intersection(dos_cwes) and any(token in text for token in ["crash", "denial", "resource", "exhaust"]):
        return "Denial of Service"

    # --------------------------------------------------------
    # REMOTE CODE EXECUTION
    # --------------------------------------------------------

    rce_cwes = {
        "CWE-78",
        "CWE-94",
        "CWE-95",
        "CWE-502",
        "CWE-917",
    }

    # CWE alone isn't always enough to prove RCE,
    # so require supporting language for some CWE types.

    if cwe_set.intersection(rce_cwes):
        if any(word in text for word in [
            "remote",
            "unauthenticated",
            "attacker",
            "execute",
            "command",
        ]) and any(word in text for word in ["execute", "command", "code", "deserializ"]):
            return "Remote Code Execution"

    explicit_rce_patterns = [
        r"remote code execution",
        r"execute arbitrary code remotely",
        r"remotely execute arbitrary code",
        r"remote attacker.*execute.*code",
        r"remote attacker.*execute.*command",
        r"execute arbitrary commands.*remote",
        r"execute arbitrary commands remotely",
        r"remote.*code.*execution",
        r"remote.*command.*execution",
    ]

    for pattern in explicit_rce_patterns:
        if re.search(pattern, text):
            return "Remote Code Execution"

    # --------------------------------------------------------
    # OTHER
    # --------------------------------------------------------

    return "Other"


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(cvss, kev):
    """
    Project risk formula:

    risk = CVSS
    if KEV:
        risk = CVSS + 1.5

    Maximum = 10
    """

    if cvss == "":
        return ""

    risk = float(cvss)

    if kev:
        risk += 1.5

    risk = min(risk, 10.0)

    return round(risk, 2)


# ============================================================
# STREAM NVD JSON
# ============================================================

def stream_nvd_records(json_file):
    """
    Stream CVE records from a large NVD JSON file.

    Requires the 'ijson' package because the NVD files
    are too large to safely load with json.load().
    """

    try:
        import ijson
    except ImportError:
        print("\nERROR: ijson is not installed.")
        print("Run this command:")
        print("pip install ijson")
        raise

    print(f"\nReading: {json_file}")

    with open(json_file, "rb") as f:

        for item in ijson.items(f, "vulnerabilities.item"):

            cve = item.get("cve", {})

            if cve:
                yield cve


# ============================================================
# RESERVOIR SAMPLING
# ============================================================

class CategorySampler:
    """
    Keeps a random sample of records without storing every CVE
    in memory.
    """

    def __init__(self, limit):
        self.limit = limit
        self.items = []
        self.seen = 0

    def add(self, item):

        self.seen += 1

        if len(self.items) < self.limit:
            self.items.append(item)
            return

        replacement_index = random.randint(0, self.seen - 1)

        if replacement_index < self.limit:
            self.items[replacement_index] = item


# ============================================================
# PROCESS NVD
# ============================================================

def process_nvd(nvd_files, kev_ids):

    samplers = {
        category: CategorySampler(TARGET_PER_CATEGORY)
        for category in CATEGORIES
    }

    total_records = 0

    for year, json_file in nvd_files.items():

        print("\n" + "=" * 60)
        print(f"PROCESSING NVD {year}")
        print("=" * 60)

        year_count = 0

        for cve in stream_nvd_records(json_file):

            total_records += 1
            year_count += 1

            cve_id = cve.get("id", "").strip().upper()

            if not cve_id:
                continue

            description = get_description(cve)

            if not description:
                continue

            cwes = get_cwes(cve)

            category = classify_category(
                description,
                cwes
            )

            cvss = get_cvss_score(cve)

            kev = cve_id in kev_ids

            vendor, product = extract_vendor_product(cve)

            published = cve.get("published", "")

            if published:
                published = published[:10]

            title = create_title(
                cve_id,
                description
            )

            risk = calculate_risk(
                cvss,
                kev
            )

            record = {
                "id": cve_id,
                "title": title,
                "vendor": vendor,
                "product": product,
                "description": description,
                "cvss": cvss,
                "kev": kev,
                "published": published,
                "true_category": category,
                "true_risk_score": risk,
                "cwe": ", ".join(cwes),
            }

            samplers[category].add(record)

            if year_count % 5000 == 0:
                print(
                    f"  Processed {year_count:,} CVEs..."
                )

        print(
            f"Finished {year}: {year_count:,} CVEs"
        )

    print("\nTotal NVD records processed:", f"{total_records:,}")

    return samplers


# ============================================================
# CREATE DATASET
# ============================================================

def build_dataset(samplers):

    records = []

    print("\n" + "=" * 60)
    print("SELECTED DATA")
    print("=" * 60)

    for category in CATEGORIES:

        category_records = samplers[category].items

        print(
            f"{category}: "
            f"{len(category_records):,}"
        )

        records.extend(category_records)

    # Remove duplicate CVE IDs
    unique = {}

    for record in records:
        unique[record["id"]] = record

    records = list(unique.values())

    # Shuffle
    random.shuffle(records)

    return records


# ============================================================
# STRATIFIED 70/15/15 SPLIT
# ============================================================

def split_dataset(records):

    groups = defaultdict(list)

    for record in records:
        groups[record["true_category"]].append(record)

    train = []
    validation = []
    test = []

    for category, category_records in groups.items():

        random.shuffle(category_records)

        n = len(category_records)

        train_end = int(n * 0.70)
        validation_end = int(n * 0.85)

        train.extend(category_records[:train_end])

        validation.extend(
            category_records[
                train_end:validation_end
            ]
        )

        test.extend(
            category_records[
                validation_end:
            ]
        )

    random.shuffle(train)
    random.shuffle(validation)
    random.shuffle(test)

    # Add split field
    for record in train:
        record["dataset_split"] = "train"

    for record in validation:
        record["dataset_split"] = "validation"

    for record in test:
        record["dataset_split"] = "test"

    return train, validation, test


# ============================================================
# WRITE CSV
# ============================================================

def write_csv(filename, records):

    output_file = OUTPUT_DIR / filename

    fieldnames = [
        "id",
        "title",
        "vendor",
        "product",
        "description",
        "cvss",
        "kev",
        "published",
        "true_category",
        "true_risk_score",
        "cwe",
        "dataset_split",
    ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for record in records:
            writer.writerow(record)

    print(f"\nCreated: {output_file}")

    return output_file


# ============================================================
# WRITE SUMMARY
# ============================================================

def write_summary(records):

    output_file = OUTPUT_DIR / "dataset_summary.csv"

    counts = defaultdict(int)

    for record in records:
        key = (
            record["dataset_split"],
            record["true_category"]
        )

        counts[key] += 1

    rows = []

    for split in [
        "train",
        "validation",
        "test"
    ]:

        for category in CATEGORIES:

            rows.append({
                "dataset_split": split,
                "category": category,
                "count": counts[
                    (split, category)
                ],
            })

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "dataset_split",
                "category",
                "count",
            ]
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"Created: {output_file}")


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("CYBER THREAT DATASET BUILDER")
    print("=" * 60)

    print(f"\nProject folder:")
    print(PROJECT_ROOT)

    print(f"\nData folder:")
    print(DATA_DIR)

    # --------------------------------------------------------
    # Find files
    # --------------------------------------------------------

    nvd_files = find_nvd_files()
    kev_file = find_kev_file()

    print("\nNVD files found:")

    for year, path in nvd_files.items():
        print(f"  {year}: {path}")

    print(f"\nCISA KEV:")
    print(f"  {kev_file}")

    # --------------------------------------------------------
    # Load KEV
    # --------------------------------------------------------

    kev_ids = load_kev_ids(kev_file)

    # --------------------------------------------------------
    # Process NVD
    # --------------------------------------------------------

    samplers = process_nvd(
        nvd_files,
        kev_ids
    )

    # --------------------------------------------------------
    # Build balanced dataset
    # --------------------------------------------------------

    records = build_dataset(samplers)

    print(
        f"\nTotal selected records: "
        f"{len(records):,}"
    )

    # --------------------------------------------------------
    # Split
    # --------------------------------------------------------

    train, validation, test = split_dataset(
        records
    )

    print("\nDataset split:")
    print(f"  Training:   {len(train):,}")
    print(f"  Validation: {len(validation):,}")
    print(f"  Test:       {len(test):,}")

    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    all_records = (
        train +
        validation +
        test
    )

    # --------------------------------------------------------
    # Write files
    # --------------------------------------------------------

    write_csv(
        "threats.csv",
        all_records
    )

    write_csv(
        "threats_train.csv",
        train
    )

    write_csv(
        "threats_validation.csv",
        validation
    )

    write_csv(
        "threats_test.csv",
        test
    )

    write_summary(all_records)

    # --------------------------------------------------------
    # Finished
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("DONE!")
    print("=" * 60)

    print("\nFiles created inside data/:")
    print("  threats.csv")
    print("  threats_train.csv")
    print("  threats_validation.csv")
    print("  threats_test.csv")
    print("  dataset_summary.csv")

    print("\nIMPORTANT:")
    print(
        "The true_category values are automatically generated "
        "initial labels."
    )

    print(
        "For a defensible final ML evaluation, manually review "
        "the test-set labels before reporting accuracy."
    )


if __name__ == "__main__":
    main()
