"""
Acme Networks billing reconciliation mock data generator.

Acme Networks is a fictional enterprise infrastructure vendor (hardware +
software licenses + support contracts) selling 6- and 7-figure deals to
Fortune 500s. This generates a synthetic billing dataset for a demo where
an agent must use a sandbox to scan ~80k rows across 10 CSVs and produce a
year-end reconciliation report.

Planted issues (~$3M total $ impact + qualitative risks):
  1. Discount-tier under-billing on growing accounts
  2. Phantom usage exceeding entitlements (true-up exposure)
  3. Co-term drift on mid-contract adds
  4. Stale FX rates on EUR/GBP invoices
  5. Credit memos issued but never applied
  6. Auto-renewals fired inside the contractual notice window
  7. Annual true-up shortfalls
  8. Channel partner double-recognition
  9. Ghost support contracts on decommissioned hardware

Run: python3 generate.py
Outputs CSVs into this directory.
"""

import csv
import random
from datetime import date, timedelta
from pathlib import Path

import numpy as np

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

OUT = Path(__file__).parent
TODAY = date(2026, 5, 15)

# ---------- Reference data ----------

CURRENCIES = ["USD", "EUR", "GBP", "JPY"]
# "True" FX rates as of TODAY (used to detect stale-FX bugs)
FX_TO_USD = {"USD": 1.00, "EUR": 1.08, "GBP": 1.26, "JPY": 0.0067}
# Stale rates used in some invoices (from ~2 years ago)
FX_STALE = {"USD": 1.00, "EUR": 1.18, "GBP": 1.38, "JPY": 0.0091}

REGIONS = ["NAMER", "EMEA", "APAC", "LATAM"]
REGION_WEIGHTS = [0.55, 0.25, 0.15, 0.05]

INDUSTRIES = [
    "Financial Services", "Healthcare", "Manufacturing", "Technology",
    "Retail", "Energy", "Government", "Telecommunications",
    "Transportation", "Media", "Pharmaceuticals", "Insurance",
]

TIERS = ["Strategic", "Enterprise", "Mid-Market"]
TIER_WEIGHTS = [0.10, 0.40, 0.50]

AE_FIRST = [
    "Sarah", "Michael", "Jennifer", "David", "Lisa", "James", "Maria", "Robert",
    "Amanda", "Christopher", "Jessica", "Daniel", "Ashley", "Matthew", "Emily",
    "Andrew", "Stephanie", "Kevin", "Rachel", "Brian", "Nicole", "Jason",
    "Megan", "Ryan", "Lauren", "Eric", "Samantha", "Steven", "Heather",
    "Thomas", "Rebecca", "Justin", "Michelle", "Joshua", "Kimberly",
]
AE_LAST = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts",
]

# Procedural company name pieces. Avoid trademarked F500 names.
NAME_PREFIX = [
    "North", "South", "East", "West", "Pacific", "Atlantic", "Central",
    "Summit", "Apex", "Vertex", "Quantum", "Sterling", "Crown", "Imperial",
    "Beacon", "Pioneer", "Frontier", "Liberty", "Heritage", "Continental",
    "Meridian", "Cardinal", "Zenith", "Magellan", "Anchor", "Granite",
    "Ironwood", "Cedar", "Maple", "Birch", "Riverstone", "Blackrock",
    "Whitehall", "Goldleaf", "Silverline", "Coppertop", "Brookfield",
    "Highland", "Lakeside", "Bayshore", "Ridgeline", "Hawthorne",
    "Ashford", "Bradford", "Camden", "Dover", "Ellsworth", "Fairmont",
    "Garrison", "Hampton", "Ironside", "Kingsbury", "Lancaster",
    "Montrose", "Norwood", "Oakridge", "Pemberton", "Quincy", "Rosewood",
    "Stonebridge", "Thornton", "Underwood", "Vanguard", "Wexford",
    "Yardley", "Zephyr", "Aurelia", "Borealis", "Cascadia", "Drayton",
]
NAME_ROOT = [
    "tech", "logic", "byte", "net", "wave", "core", "stack", "node",
    "cloud", "data", "stream", "grid", "ware", "soft", "sys", "comp",
    "dyn", "form", "gen", "lab", "mech", "metr", "ops", "phase",
    "plex", "pol", "scan", "tron", "ven", "verge", "volt", "ware",
    "yield", "zone", "axion", "bridge", "drive", "edge", "flux",
]
NAME_SUFFIX = [
    "Industries", "Holdings", "Group", "Corp", "Corporation", "Systems",
    "Networks", "Technologies", "Solutions", "Enterprises", "Partners",
    "Capital", "Logistics", "Dynamics", "Labs", "Works", "International",
    "Global", "& Co.", "Trust", "Worldwide", "Resources", "Manufacturing",
    "Financial", "Insurance", "Pharmaceuticals", "Energy", "Health",
    "Aerospace", "Foods", "Beverages", "Materials", "Automotive",
]

# Fortune-500-style flagship fictional names — sprinkle these as Strategic accounts
FLAGSHIP_NAMES = [
    "Globex Industries", "Initech Financial", "Hooli Systems",
    "Pied Piper Networks", "Wonka Holdings", "Soylent Foods Corp",
    "Stark Aerospace", "Wayne Enterprises", "Cyberdyne Systems",
    "Tyrell Genetics", "Umbrella Pharmaceuticals", "Massive Dynamic",
    "Vandelay Imports", "Sterling Cooper", "Dunder Mifflin Logistics",
    "Pearson Hardman Trust", "Oceanic Airlines", "InGen Bio",
    "Weyland Industries", "Aperture Labs", "Nakatomi Trading",
    "Rekall Solutions", "OsCorp Industries", "LexCorp Capital",
    "Wallace Genetics", "Spectre Holdings", "Yoyodyne Propulsion",
    "Bluth Real Estate", "Krusty Foods", "Buy n Large Retail",
    "Cogswell Cogs", "Spacely Sprockets", "Planet Express Logistics",
    "Acme Anvil Co.", "Daily Planet Media", "Wernham Hogg Paper",
    "Vehement Capital", "Strickland Propane", "Compeyson Trust",
    "Krell Industries", "Lockmart Defense", "Northbrook Energy",
    "Castle Black Holdings", "Tarly Manufacturing", "Lannister Capital",
    "Stark Industries Northeast", "Targaryen Group", "Whitewalker Cold Storage",
    "Hightower Trading", "Greyjoy Maritime",
]

# Product catalog — 80 SKUs across categories
def build_products():
    rows = []
    sku_id = 1
    # Hardware (40 SKUs)
    hw_families = [
        ("AX", "Access Switch", (2500, 12000)),
        ("CR", "Core Router", (45000, 180000)),
        ("FW", "Firewall Appliance", (8000, 65000)),
        ("WAP", "Wireless Access Point", (450, 1800)),
        ("LB", "Load Balancer", (25000, 95000)),
        ("SD", "SD-WAN Gateway", (6000, 28000)),
    ]
    for fam_code, fam_name, (lo, hi) in hw_families:
        for i in range(1, 8):
            rows.append({
                "sku": f"{fam_code}-{1000+i*100}",
                "name": f"Acme {fam_name} {fam_code}-{1000+i*100}",
                "category": "hardware",
                "list_price_usd": round(lo + (hi - lo) * (i / 7), 2),
                "billing_model": "one_time",
                "uom": "unit",
            })
            sku_id += 1
            if len(rows) >= 40:
                break
        if len(rows) >= 40:
            break
    # Software subscriptions (20 SKUs)
    sw_subs = [
        ("NOC", "NOC Platform", "per_seat_month", (45, 180)),
        ("SEC", "Security Suite", "per_seat_month", (60, 250)),
        ("OBS", "Observability Cloud", "per_host_month", (25, 120)),
        ("SDC", "SD-WAN Cloud Controller", "per_site_month", (200, 800)),
        ("ZTN", "Zero-Trust Network", "per_user_month", (35, 140)),
    ]
    for fam_code, fam_name, model, (lo, hi) in sw_subs:
        for i in range(1, 5):
            rows.append({
                "sku": f"SW-{fam_code}-{100+i*10}",
                "name": f"Acme {fam_name} Tier {i}",
                "category": "software_subscription",
                "list_price_usd": round(lo + (hi - lo) * (i / 4), 2),
                "billing_model": model,
                "uom": model.split("_")[1],  # seat/host/site/user
            })
    # Support tiers (12 SKUs — Bronze/Silver/Gold/Platinum × 3 hardware classes)
    for tier, pct_low, pct_high in [
        ("Bronze", 0.08, 0.10),
        ("Silver", 0.12, 0.15),
        ("Gold", 0.18, 0.22),
        ("Platinum", 0.25, 0.30),
    ]:
        for cls, mult in [("Edge", 1.0), ("Core", 2.0), ("DC", 3.5)]:
            rows.append({
                "sku": f"SUP-{tier[:3].upper()}-{cls.upper()}",
                "name": f"Acme {tier} Support — {cls} Class",
                "category": "support",
                # Expressed as annual $/unit-of-hardware-supported
                "list_price_usd": round(5000 * mult * ((pct_low + pct_high) / 2) * 10, 2),
                "billing_model": "annual",
                "uom": "contract_year",
            })
    # Pro services (8 SKUs)
    services = [
        ("Implementation — Standard", 45000),
        ("Implementation — Enterprise", 180000),
        ("Network Design Workshop", 22000),
        ("Migration Services", 95000),
        ("Custom Integration Dev", 140000),
        ("Onsite Training (5-day)", 38000),
        ("Health Check Assessment", 18000),
        ("24/7 Embedded Engineer (annual)", 320000),
    ]
    for name, price in services:
        code = "".join(w[0] for w in name.split() if w[0].isalpha())[:4].upper()
        rows.append({
            "sku": f"PS-{code}",
            "name": f"Acme {name}",
            "category": "services",
            "list_price_usd": float(price),
            "billing_model": "one_time",
            "uom": "engagement",
        })
    return rows


# ---------- Generators ----------

def gen_accounts(n=500):
    rows = []
    used_names = set()
    # First, flagships as Strategic
    for i, name in enumerate(FLAGSHIP_NAMES[:50]):
        used_names.add(name)
        rows.append({
            "account_id": f"ACC-{10001+i:05d}",
            "name": name,
            "industry": random.choice(INDUSTRIES),
            "region": np.random.choice(REGIONS, p=REGION_WEIGHTS),
            "tier": "Strategic",
            "account_exec": f"{random.choice(AE_FIRST)} {random.choice(AE_LAST)}",
            "signup_date": (date(2019, 1, 1) + timedelta(days=random.randint(0, 365 * 4))).isoformat(),
            "channel_partner_id": "" if random.random() < 0.7 else f"CP-{random.randint(100, 199)}",
        })
    # Then procedural
    while len(rows) < n:
        style = random.random()
        if style < 0.5:
            name = f"{random.choice(NAME_PREFIX)}{random.choice(NAME_ROOT).capitalize()} {random.choice(NAME_SUFFIX)}"
        elif style < 0.8:
            name = f"{random.choice(NAME_PREFIX)} {random.choice(NAME_SUFFIX)}"
        else:
            name = f"{random.choice(NAME_PREFIX)}-{random.choice(NAME_PREFIX)} {random.choice(NAME_SUFFIX)}"
        if name in used_names:
            continue
        used_names.add(name)
        tier = np.random.choice(TIERS[1:], p=[0.45, 0.55])
        rows.append({
            "account_id": f"ACC-{10001+len(rows):05d}",
            "name": name,
            "industry": random.choice(INDUSTRIES),
            "region": np.random.choice(REGIONS, p=REGION_WEIGHTS),
            "tier": tier,
            "account_exec": f"{random.choice(AE_FIRST)} {random.choice(AE_LAST)}",
            "signup_date": (date(2020, 1, 1) + timedelta(days=random.randint(0, 365 * 5))).isoformat(),
            "channel_partner_id": "" if random.random() < 0.75 else f"CP-{random.randint(100, 199)}",
        })
    return rows


def gen_contracts(accounts, products):
    """1–5 contracts per account. Mixed currencies, mixed durations."""
    contracts = []
    line_items = []
    contract_id = 70001
    li_id = 500001

    products_by_cat = {}
    for p in products:
        products_by_cat.setdefault(p["category"], []).append(p)

    for acc in accounts:
        # Strategic accounts get more contracts and bigger deals — `size_mult`
        # scales line-item quantities (and therefore real invoice amounts).
        if acc["tier"] == "Strategic":
            n_contracts = random.randint(3, 5)
            size_mult = random.uniform(1.5, 3.0)
        elif acc["tier"] == "Enterprise":
            n_contracts = random.randint(2, 4)
            size_mult = random.uniform(0.7, 1.5)
        else:
            n_contracts = random.randint(1, 2)
            size_mult = random.uniform(0.3, 0.8)

        currency = np.random.choice(
            CURRENCIES, p=[0.70, 0.15, 0.10, 0.05]
        ) if acc["region"] != "NAMER" else (
            np.random.choice(CURRENCIES, p=[0.92, 0.04, 0.03, 0.01])
        )

        for _ in range(n_contracts):
            start = date(2022, 1, 1) + timedelta(days=random.randint(0, 365 * 4))
            term_years = np.random.choice([1, 2, 3, 5], p=[0.25, 0.20, 0.40, 0.15])
            end = date(start.year + term_years, start.month, min(start.day, 28))

            # Status based on dates
            if end < TODAY:
                status = np.random.choice(["expired", "terminated"], p=[0.85, 0.15])
            else:
                status = "active"

            contract_value = 0.0
            sold_via_partner = bool(acc["channel_partner_id"]) and random.random() < 0.6

            # Line items: mix of categories
            n_li = random.randint(4, 14)
            this_contract_lis = []
            for _ in range(n_li):
                cat = np.random.choice(
                    ["hardware", "software_subscription", "support", "services"],
                    p=[0.30, 0.35, 0.25, 0.10],
                )
                product = random.choice(products_by_cat[cat])
                if cat == "hardware":
                    qty = max(1, int(random.randint(1, 12) * size_mult))
                elif cat == "software_subscription":
                    qty = max(10, int(random.randint(25, 800) * size_mult))
                elif cat == "support":
                    qty = max(1, int(random.randint(1, 10) * size_mult))
                else:
                    qty = 1

                discount = round(np.random.choice(
                    [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35],
                    p=[0.10, 0.10, 0.20, 0.20, 0.20, 0.10, 0.07, 0.03],
                ), 2)
                unit_price_usd = product["list_price_usd"] * (1 - discount)
                unit_price = unit_price_usd / FX_TO_USD[currency]

                billing_freq = {
                    "hardware": "one_time",
                    "software_subscription": np.random.choice(["monthly", "annual"], p=[0.55, 0.45]),
                    "support": "annual",
                    "services": "one_time",
                }[cat]

                # Line item period: starts at contract start unless mid-contract add
                li_start = start
                li_end = end
                if random.random() < 0.06:  # mid-contract add
                    li_start = start + timedelta(days=random.randint(60, max(61, term_years * 365 - 90)))

                if billing_freq == "one_time":
                    li_value = unit_price_usd * qty
                elif billing_freq == "monthly":
                    months = max(1, (li_end.year - li_start.year) * 12 + (li_end.month - li_start.month))
                    li_value = unit_price_usd * qty * months
                else:  # annual
                    years = max(1, li_end.year - li_start.year)
                    li_value = unit_price_usd * qty * years

                contract_value += li_value

                this_contract_lis.append({
                    "line_item_id": f"LI-{li_id:07d}",
                    "contract_id": f"CON-{contract_id:06d}",
                    "account_id": acc["account_id"],
                    "sku": product["sku"],
                    "category": cat,
                    "quantity": qty,
                    "list_price_usd": product["list_price_usd"],
                    "discount_pct": discount,
                    "unit_price": round(unit_price, 2),
                    "currency": currency,
                    "billing_freq": billing_freq,
                    "start_date": li_start.isoformat(),
                    "end_date": li_end.isoformat(),
                })
                li_id += 1

            contracts.append({
                "contract_id": f"CON-{contract_id:06d}",
                "account_id": acc["account_id"],
                "msa_ref": f"MSA-{acc['account_id'][-5:]}-{random.randint(1, 9)}",
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
                "term_years": int(term_years),
                "total_value_usd": round(contract_value, 2),
                "currency": currency,
                "payment_terms_days": int(np.random.choice([30, 45, 60, 90], p=[0.55, 0.25, 0.15, 0.05])),
                "status": status,
                "auto_renew": bool(random.random() < 0.55),
                "renewal_notice_days": int(np.random.choice([30, 60, 90, 120], p=[0.20, 0.30, 0.40, 0.10])),
                "sold_via_partner": sold_via_partner,
            })
            line_items.extend(this_contract_lis)
            contract_id += 1

    return contracts, line_items


def gen_entitlements(line_items):
    """One row per recurring software/support line item — what the customer is licensed for."""
    rows = []
    ent_id = 800001
    for li in line_items:
        if li["category"] not in ("software_subscription", "support"):
            continue
        rows.append({
            "entitlement_id": f"ENT-{ent_id:07d}",
            "account_id": li["account_id"],
            "contract_id": li["contract_id"],
            "line_item_id": li["line_item_id"],
            "sku": li["sku"],
            "quantity_licensed": li["quantity"],
            "start_date": li["start_date"],
            "end_date": li["end_date"],
        })
        ent_id += 1
    return rows


def gen_usage(entitlements, products):
    """Monthly usage telemetry for software_subscription entitlements."""
    rows = []
    use_id = 900001
    prod_by_sku = {p["sku"]: p for p in products}
    for ent in entitlements:
        prod = prod_by_sku.get(ent["sku"])
        if not prod or prod["category"] != "software_subscription":
            continue
        start = date.fromisoformat(ent["start_date"])
        end = min(date.fromisoformat(ent["end_date"]), TODAY)
        cur = date(start.year, start.month, 1)
        # Most accounts use 50-90% of entitlement
        base_util = random.uniform(0.50, 0.90)
        drift = random.uniform(-0.01, 0.02)  # monthly drift
        while cur <= end:
            util = max(0.05, min(1.5, base_util + drift * ((cur.year - start.year) * 12 + cur.month - start.month)))
            used = int(ent["quantity_licensed"] * util)
            rows.append({
                "usage_id": f"USE-{use_id:07d}",
                "account_id": ent["account_id"],
                "entitlement_id": ent["entitlement_id"],
                "sku": ent["sku"],
                "period_month": cur.isoformat(),
                "quantity_used": used,
            })
            use_id += 1
            # advance one month
            if cur.month == 12:
                cur = date(cur.year + 1, 1, 1)
            else:
                cur = date(cur.year, cur.month + 1, 1)
    return rows


def gen_invoices_and_payments(contracts, line_items):
    """Generate invoices from billing schedules, then payments mostly 1:1."""
    invoices = []
    payments = []
    inv_id = 200001
    pay_id = 300001

    lis_by_contract = {}
    for li in line_items:
        lis_by_contract.setdefault(li["contract_id"], []).append(li)

    for contract in contracts:
        c_lis = lis_by_contract.get(contract["contract_id"], [])
        currency = contract["currency"]
        terms = contract["payment_terms_days"]
        cstart = date.fromisoformat(contract["start_date"])
        cend = date.fromisoformat(contract["end_date"])

        # One-time line items → single invoice at contract start
        one_time = [li for li in c_lis if li["billing_freq"] == "one_time"]
        if one_time:
            amt = sum(li["unit_price"] * li["quantity"] for li in one_time)
            issued = cstart
            due = issued + timedelta(days=terms)
            paid_status = np.random.choice(
                ["paid", "open", "overdue", "void"],
                p=[0.88, 0.05, 0.05, 0.02],
            )
            if issued > TODAY:
                paid_status = "open"
            invoices.append({
                "invoice_id": f"INV-{inv_id:07d}",
                "contract_id": contract["contract_id"],
                "account_id": contract["account_id"],
                "invoice_type": "one_time",
                "period_start": issued.isoformat(),
                "period_end": issued.isoformat(),
                "amount": round(amt, 2),
                "currency": currency,
                "fx_rate_to_usd": FX_TO_USD[currency],
                "issued_date": issued.isoformat(),
                "due_date": due.isoformat(),
                "status": paid_status,
            })
            if paid_status == "paid":
                pay_date = issued + timedelta(days=random.randint(5, min(terms + 15, 90)))
                payments.append({
                    "payment_id": f"PAY-{pay_id:07d}",
                    "invoice_id": f"INV-{inv_id:07d}",
                    "account_id": contract["account_id"],
                    "paid_date": pay_date.isoformat(),
                    "amount": round(amt, 2),
                    "currency": currency,
                    "method": np.random.choice(["wire", "ach", "credit_card", "check"], p=[0.55, 0.25, 0.10, 0.10]),
                    "status": "succeeded",
                })
                pay_id += 1
            inv_id += 1

        # Recurring (monthly + annual) — iterate periods
        recurring = [li for li in c_lis if li["billing_freq"] in ("monthly", "annual")]
        # Group by billing freq
        for freq in ("monthly", "annual"):
            lis = [li for li in recurring if li["billing_freq"] == freq]
            if not lis:
                continue
            # Determine periods
            period_start = max(cstart, min(date.fromisoformat(li["start_date"]) for li in lis))
            while period_start < min(cend, TODAY + timedelta(days=60)):
                if freq == "monthly":
                    if period_start.month == 12:
                        period_end = date(period_start.year + 1, 1, 1) - timedelta(days=1)
                    else:
                        period_end = date(period_start.year, period_start.month + 1, 1) - timedelta(days=1)
                else:
                    period_end = date(period_start.year + 1, period_start.month, 1) - timedelta(days=1)

                # Sum line items active in this period
                amt = 0.0
                active_count = 0
                for li in lis:
                    li_start = date.fromisoformat(li["start_date"])
                    li_end = date.fromisoformat(li["end_date"])
                    if li_start <= period_end and li_end >= period_start:
                        if freq == "monthly":
                            amt += li["unit_price"] * li["quantity"]
                        else:
                            amt += li["unit_price"] * li["quantity"]
                        active_count += 1
                if active_count == 0 or amt <= 0:
                    period_start = period_end + timedelta(days=1)
                    continue

                issued = period_start
                due = issued + timedelta(days=terms)
                if issued > TODAY:
                    paid_status = "open"
                else:
                    paid_status = np.random.choice(
                        ["paid", "open", "overdue", "void"],
                        p=[0.92, 0.03, 0.04, 0.01],
                    )

                invoices.append({
                    "invoice_id": f"INV-{inv_id:07d}",
                    "contract_id": contract["contract_id"],
                    "account_id": contract["account_id"],
                    "invoice_type": freq,
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat(),
                    "amount": round(amt, 2),
                    "currency": currency,
                    "fx_rate_to_usd": FX_TO_USD[currency],
                    "issued_date": issued.isoformat(),
                    "due_date": due.isoformat(),
                    "status": paid_status,
                })
                if paid_status == "paid":
                    pay_date = issued + timedelta(days=random.randint(5, min(terms + 15, 90)))
                    payments.append({
                        "payment_id": f"PAY-{pay_id:07d}",
                        "invoice_id": f"INV-{inv_id:07d}",
                        "account_id": contract["account_id"],
                        "paid_date": pay_date.isoformat(),
                        "amount": round(amt, 2),
                        "currency": currency,
                        "method": np.random.choice(["wire", "ach", "credit_card", "check"], p=[0.55, 0.25, 0.10, 0.10]),
                        "status": "succeeded",
                    })
                    pay_id += 1
                inv_id += 1

                # advance period
                period_start = period_end + timedelta(days=1)

    return invoices, payments


def gen_credit_memos(invoices):
    """~200 credit memos. ~15% are 'issued but never applied' (planted bug)."""
    rows = []
    cm_id = 400001
    paid_invs = [i for i in invoices if i["status"] == "paid"]
    sample_size = min(200, len(paid_invs))
    sampled = random.sample(paid_invs, sample_size)
    for inv in sampled:
        amt = round(inv["amount"] * random.uniform(0.01, 0.05), 2)
        reason = np.random.choice([
            "billing_error", "service_credit_sla", "negotiated_discount",
            "duplicate_charge", "early_termination_adjustment", "goodwill",
        ], p=[0.25, 0.20, 0.20, 0.10, 0.15, 0.10])
        applied = random.random() < 0.85  # 15% unapplied (planted bug)
        rows.append({
            "credit_memo_id": f"CM-{cm_id:06d}",
            "account_id": inv["account_id"],
            "related_invoice_id": inv["invoice_id"],
            "amount": amt,
            "currency": inv["currency"],
            "issued_date": (date.fromisoformat(inv["issued_date"]) + timedelta(days=random.randint(10, 120))).isoformat(),
            "reason": reason,
            "applied_to_invoice_id": "" if not applied else f"INV-{random.randint(200001, 200001 + len(invoices) - 1):07d}",
            "applied_date": "" if not applied else (date.fromisoformat(inv["issued_date"]) + timedelta(days=random.randint(30, 180))).isoformat(),
        })
        cm_id += 1
    return rows


def gen_renewals(contracts):
    """Renewals: every expiring contract gets a renewal row. Some auto-renewed inside notice window."""
    rows = []
    ren_id = 600001
    for c in contracts:
        end = date.fromisoformat(c["end_date"])
        # Generate renewal row if contract ended in the past or ends within 12 months
        if end < TODAY - timedelta(days=365 * 2) or end > TODAY + timedelta(days=365):
            continue
        if c["auto_renew"]:
            outcome = np.random.choice(
                ["auto_renewed", "renewed_negotiated", "cancelled_by_customer", "pending"],
                p=[0.55, 0.20, 0.10, 0.15],
            )
        else:
            outcome = np.random.choice(
                ["renewed_negotiated", "cancelled_by_customer", "pending", "expired_no_action"],
                p=[0.45, 0.20, 0.25, 0.10],
            )
        if end > TODAY:
            outcome = "pending"

        # Notice date — should be at least renewal_notice_days before end
        notice_required = end - timedelta(days=c["renewal_notice_days"])
        # Most legit notices go out 7-30 days before required deadline
        notice_sent = notice_required - timedelta(days=random.randint(0, 30))

        rows.append({
            "renewal_id": f"REN-{ren_id:06d}",
            "contract_id": c["contract_id"],
            "account_id": c["account_id"],
            "original_end_date": c["end_date"],
            "renewal_notice_required_days": c["renewal_notice_days"],
            "notice_sent_date": notice_sent.isoformat(),
            "outcome": outcome,
            "new_term_start": (end + timedelta(days=1)).isoformat() if outcome in ("auto_renewed", "renewed_negotiated") else "",
            "new_term_end": (end + timedelta(days=365 * c["term_years"])).isoformat() if outcome in ("auto_renewed", "renewed_negotiated") else "",
        })
        ren_id += 1
    return rows


def gen_change_orders(contracts):
    """Mid-contract change orders — qty increases, SKU adds, support upgrades."""
    rows = []
    co_id = 700001
    contracts_active_or_recent = [c for c in contracts if c["status"] in ("active", "expired")]
    sample = random.sample(contracts_active_or_recent, min(400, len(contracts_active_or_recent)))
    for c in sample:
        cstart = date.fromisoformat(c["start_date"])
        cend = date.fromisoformat(c["end_date"])
        co_date = cstart + timedelta(days=random.randint(60, max(61, (cend - cstart).days - 30)))
        change_type = np.random.choice(
            ["add_skus", "increase_qty", "tier_upgrade", "early_termination_partial"],
            p=[0.40, 0.35, 0.20, 0.05],
        )
        rows.append({
            "change_order_id": f"CO-{co_id:06d}",
            "contract_id": c["contract_id"],
            "account_id": c["account_id"],
            "change_type": change_type,
            "effective_date": co_date.isoformat(),
            "delta_value_usd": round(random.uniform(5000, 250000), 2),
            "notes": {
                "add_skus": "Customer added new product SKUs mid-term",
                "increase_qty": "Quantity increase on existing line items",
                "tier_upgrade": "Support tier upgraded",
                "early_termination_partial": "Partial termination of select line items",
            }[change_type],
        })
        co_id += 1
    return rows


# ---------- Planted bug injection ----------

def inject_bugs(contracts, line_items, entitlements, usage,
                invoices, payments, credit_memos, renewals):
    """Plant the 9 bug classes. Mutates inputs in place."""

    leakage_log = []  # internal — printed at end as a sanity check

    # 1. Discount-tier under-billing: customer paid less than contracted because
    #    a discount-tier step-down was applied to invoices it shouldn't have.
    #    Affect the LAST 2-4 recurring invoices for ~14 contracts at 8-15% off.
    target_contracts = random.sample(contracts, 14)
    for c in target_contracts:
        disc = random.uniform(0.08, 0.15)
        c_invs = sorted(
            [inv for inv in invoices
             if inv["contract_id"] == c["contract_id"]
             and inv["invoice_type"] in ("monthly", "annual")],
            key=lambda x: x["issued_date"],
        )
        for inv in c_invs[-random.randint(2, 4):]:
            original = inv["amount"]
            inv["amount"] = round(original * (1 - disc), 2)
            delta_usd = (original - inv["amount"]) * FX_TO_USD[inv["currency"]]
            leakage_log.append(("under_billing_discount_misapplied", c["account_id"], delta_usd))

    # 2. Phantom usage: for ~12 software entitlements, bump usage 10-30% above
    #    licensed qty. Only counts the OVERAGE over the last 3 months as
    #    recoverable revenue (most enterprise contracts true-up annually).
    sw_ents = [e for e in entitlements if e["sku"].startswith("SW-")]
    target_ents = random.sample(sw_ents, min(25, len(sw_ents)))
    target_ent_ids = {e["entitlement_id"] for e in target_ents}
    for u in usage:
        if u["entitlement_id"] in target_ent_ids:
            ent = next(e for e in entitlements if e["entitlement_id"] == u["entitlement_id"])
            over_factor = random.uniform(1.15, 1.40)
            u["quantity_used"] = int(ent["quantity_licensed"] * over_factor)
    for e in target_ents:
        li = next((l for l in line_items if l["line_item_id"] == e["line_item_id"]), None)
        if li:
            avg_over = e["quantity_licensed"] * 0.12
            # Recoverable: 4 months of overage at 50% recovery
            leakage_log.append((
                "phantom_usage_overage", e["account_id"],
                avg_over * li["unit_price"] * 4 * FX_TO_USD[li["currency"]] * 0.5,
            ))

    # 3. Co-term drift: mid-contract adds whose end_date doesn't match parent contract
    mid_contract_adds = [
        li for li in line_items
        if li["start_date"] != "" and date.fromisoformat(li["start_date"]) >
        date.fromisoformat(next(c["start_date"] for c in contracts if c["contract_id"] == li["contract_id"])) + timedelta(days=90)
    ]
    drift_targets = random.sample(mid_contract_adds, min(14, len(mid_contract_adds)))
    for li in drift_targets:
        li["end_date"] = (date.fromisoformat(li["start_date"]) + timedelta(days=365)).isoformat()
        # Impact: ~3 months of pro-rated overlap that needs unwinding
        if li["billing_freq"] == "monthly":
            monthly = li["unit_price"] * li["quantity"]
        else:
            monthly = li["unit_price"] * li["quantity"] / 12
        leakage_log.append(("co_term_drift", li["account_id"],
                            monthly * 3 * FX_TO_USD[li["currency"]] * 0.3))

    # 4. Stale FX: for ~15 EUR/GBP invoices issued in last 12 months, store stale fx_rate
    non_usd = [i for i in invoices if i["currency"] in ("EUR", "GBP") and
               date.fromisoformat(i["issued_date"]) > TODAY - timedelta(days=365)]
    stale_targets = random.sample(non_usd, min(20, len(non_usd)))
    for inv in stale_targets:
        inv["fx_rate_to_usd"] = FX_STALE[inv["currency"]]
        delta = inv["amount"] * (FX_STALE[inv["currency"]] - FX_TO_USD[inv["currency"]])
        leakage_log.append(("stale_fx", inv["account_id"], delta))

    # 5. Credit memos unapplied — already 30% unapplied by default; sum impact
    for cm in credit_memos:
        if cm["applied_to_invoice_id"] == "":
            leakage_log.append(("unapplied_credit_memo", cm["account_id"],
                                cm["amount"] * FX_TO_USD[cm["currency"]] * -1))  # negative = customer credit owed

    # 6. Auto-renewals fired inside notice window — adjust notice_sent_date on
    #    ~25 auto-renewed renewals to be AFTER notice deadline
    auto_ren = [r for r in renewals if r["outcome"] == "auto_renewed"]
    notice_targets = random.sample(auto_ren, min(25, len(auto_ren)))
    for r in notice_targets:
        # Set notice_sent to ~5-15 days before contract end (well inside notice window)
        end = date.fromisoformat(r["original_end_date"])
        r["notice_sent_date"] = (end - timedelta(days=random.randint(0, 14))).isoformat()
        # Not a $ leakage — legal/compliance risk

    # 7. Annual true-up shortfalls — ~6 software contracts where usage grew but
    #    no annual true-up invoice was generated. Naturally true in this dataset
    #    since we don't generate true-up invoices; flag accounts with growth.
    for e in random.sample(sw_ents, min(15, len(sw_ents))):
        li = next((l for l in line_items if l["line_item_id"] == e["line_item_id"]), None)
        if li:
            leakage_log.append(("missing_true_up", e["account_id"],
                                e["quantity_licensed"] * 0.12 * li["unit_price"] * FX_TO_USD[li["currency"]] * 3))

    # 8. Channel partner double-recognition: for ~5 contracts sold via partner,
    #    duplicate ONE recurring invoice (smaller $) under a "direct" channel.
    partner_contracts = [c for c in contracts if c["sold_via_partner"]]
    dup_targets = random.sample(partner_contracts, min(5, len(partner_contracts)))
    next_inv_id = max(int(i["invoice_id"][4:]) for i in invoices) + 1
    next_pay_id = max(int(p["payment_id"][4:]) for p in payments) + 1
    for c in dup_targets:
        # Pick the smallest recurring invoice on the contract — easier for the
        # agent to find, and keeps planted impact modest.
        c_invs = sorted(
            [i for i in invoices
             if i["contract_id"] == c["contract_id"]
             and i["invoice_type"] in ("monthly", "annual")],
            key=lambda x: x["amount"],
        )
        for inv in c_invs[:1]:
            dup = dict(inv)
            dup["invoice_id"] = f"INV-{next_inv_id:07d}"
            # Mark with direct channel (a notes field would be cleaner — but our schema
            # doesn't have one. Instead, slight amount drift makes it look real.)
            invoices.append(dup)
            leakage_log.append(("channel_double_count", c["account_id"],
                                inv["amount"] * FX_TO_USD[inv["currency"]] * -1))
            # Also duplicate payment if original was paid
            if inv["status"] == "paid":
                for pay in payments:
                    if pay["invoice_id"] == inv["invoice_id"]:
                        dup_pay = dict(pay)
                        dup_pay["payment_id"] = f"PAY-{next_pay_id:07d}"
                        dup_pay["invoice_id"] = dup["invoice_id"]
                        payments.append(dup_pay)
                        next_pay_id += 1
                        break
            next_inv_id += 1

    # 9. Ghost support contracts: ~20 support line items whose hardware was
    #    "decommissioned" (we'll mark via a separate column on line_items,
    #    but to keep schema clean: just make support contracts that bill long
    #    after the parent hardware line item ended).
    #    Simulate by: for some support LIs, extend end_date 18 months past the
    #    hardware LI in the same contract.
    # Bias toward smaller support line items to keep planted impact modest.
    support_lis = sorted(
        [li for li in line_items if li["category"] == "support"],
        key=lambda x: x["unit_price"] * x["quantity"],
    )
    # Pick from the bottom three-quarters — meaningful but not jumbo.
    pool = support_lis[: max(1, 3 * len(support_lis) // 4)]
    ghost_targets = random.sample(pool, min(8, len(pool)))
    for li in ghost_targets:
        # Find a hardware LI in the same contract — the support is billing on
        # hardware that was "decommissioned". Detectable by joining support→hardware.
        hw = [h for h in line_items if h["contract_id"] == li["contract_id"] and h["category"] == "hardware"]
        if hw:
            target_hw = random.choice(hw)
            target_hw["end_date"] = (date.fromisoformat(target_hw["start_date"]) + timedelta(days=180)).isoformat()
            leakage_log.append(("ghost_support_contract", li["account_id"],
                                li["unit_price"] * li["quantity"] * FX_TO_USD[li["currency"]] * -1))

    return leakage_log


# ---------- Write CSVs ----------

def write_csv(filename, rows):
    if not rows:
        return
    path = OUT / filename
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def main():
    print("Generating Acme Networks billing data...")

    products = build_products()
    print(f"  products:        {len(products):>6}")

    accounts = gen_accounts(500)
    print(f"  accounts:        {len(accounts):>6}")

    contracts, line_items = gen_contracts(accounts, products)
    print(f"  contracts:       {len(contracts):>6}")
    print(f"  line_items:      {len(line_items):>6}")

    entitlements = gen_entitlements(line_items)
    print(f"  entitlements:    {len(entitlements):>6}")

    usage = gen_usage(entitlements, products)
    print(f"  usage_telemetry: {len(usage):>6}")

    invoices, payments = gen_invoices_and_payments(contracts, line_items)
    print(f"  invoices:        {len(invoices):>6}")
    print(f"  payments:        {len(payments):>6}")

    credit_memos = gen_credit_memos(invoices)
    print(f"  credit_memos:    {len(credit_memos):>6}")

    renewals = gen_renewals(contracts)
    print(f"  renewals:        {len(renewals):>6}")

    change_orders = gen_change_orders(contracts)
    print(f"  change_orders:   {len(change_orders):>6}")

    print("\nInjecting planted bugs...")
    leakage = inject_bugs(contracts, line_items, entitlements, usage,
                          invoices, payments, credit_memos, renewals)

    print("\nWriting CSVs...")
    write_csv("products.csv", products)
    write_csv("accounts.csv", accounts)
    write_csv("contracts.csv", contracts)
    write_csv("contract_line_items.csv", line_items)
    write_csv("entitlements.csv", entitlements)
    write_csv("usage_telemetry.csv", usage)
    write_csv("invoices.csv", invoices)
    write_csv("payments.csv", payments)
    write_csv("credit_memos.csv", credit_memos)
    write_csv("renewals.csv", renewals)
    write_csv("change_orders.csv", change_orders)

    # Summary of planted impact (for internal sanity check)
    by_cat = {}
    for cat, _, amt in leakage:
        by_cat[cat] = by_cat.get(cat, 0) + amt
    total = sum(abs(v) for v in by_cat.values())
    print("\nPlanted bug impact (internal sanity check):")
    for k, v in sorted(by_cat.items(), key=lambda x: -abs(x[1])):
        print(f"  {k:<35} ${v:>15,.0f}")
    print(f"  {'TOTAL (abs)':<35} ${total:>15,.0f}")

    # File sizes
    print("\nOn-disk sizes:")
    total_bytes = 0
    for f in sorted(OUT.glob("*.csv")):
        sz = f.stat().st_size
        total_bytes += sz
        print(f"  {f.name:<28} {sz/1024:>8.1f} KB")
    print(f"  {'TOTAL':<28} {total_bytes/1024/1024:>8.2f} MB")


if __name__ == "__main__":
    main()
